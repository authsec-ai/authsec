// AuthSec backend — Hetzner single-node deploy.
//
// THIS FILE IS THE PIPELINE. It only runs if the Jenkins job is configured as
// "Pipeline script from SCM" pointing at this path. If the job holds an inline
// script instead, this file is decorative and editing it changes nothing — which
// was the state until now, and cost real debugging time.
//
// Job configuration this expects (set once, in Jenkins):
//   Definition   Pipeline script from SCM
//   SCM          Git — https://github.com/authsec-ai/authsec.git
//   Credentials  github-pat
//   Branch       */authsec-staging
//   Script Path  Jenkinsfile
//
// Consequence worth knowing: only authsec-staging deploys. Pushing any other
// branch does nothing at all — no build, no error. That is deliberate, and the
// Identify stage below prints what shipped so it is never a mystery.
//
// There is no Checkout stage: with SCM-defined pipelines Jenkins has already
// checked the repo out into the workspace before it reads this file. Re-cloning
// here would risk building a different commit than the one that triggered.

pipeline {
    agent any

    triggers { githubPush() }

    options {
        buildDiscarder logRotator(numToKeepStr: '15')
        // Two deploys recreating the same container race and can leave the
        // stack running an image neither build produced.
        disableConcurrentBuilds()
        timeout(time: 20, unit: 'MINUTES')
        timestamps()
    }

    environment {
        SERVICE   = 'backend'
        IMAGE     = 'authsec-backend:latest'
        ROLLBACK  = 'authsec-backend:previous'
        STACK_DIR = '/opt/authsec'
        // Internal, not https://app.authsec.ai — a public URL adds nginx, DNS
        // and TLS as failure modes for what is only an app deploy, so a healthy
        // backend behind a sulking proxy would fail this build for the wrong
        // reason.
        HEALTH_URL = 'http://127.0.0.1:7468/authsec/uflow/health'
    }

    stages {
        stage('Identify') {
            steps {
                script {
                    // Recorded once so the post block can name the commit
                    // without shelling out again.
                    env.DEPLOY_SHA = sh(returnStdout: true,
                        script: 'git rev-parse --short HEAD').trim()
                }
                sh '''
                    echo "branch : $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
                    echo "commit : $(git rev-parse --short HEAD)"
                    echo "subject: $(git log -1 --pretty=%s)"
                    echo "author : $(git log -1 --pretty=%an)"
                '''
            }
        }

        stage('Tag rollback point') {
            steps {
                // Keep the currently-deployed image reachable under a second tag
                // BEFORE the build overwrites :latest. Without this there is
                // nothing to go back to and a bad deploy leaves production down
                // until someone rebuilds by hand.
                sh '''
                    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
                        docker tag "$IMAGE" "$ROLLBACK"
                        echo "rollback point: $(docker image inspect "$ROLLBACK" --format '{{.Id}}')"
                    else
                        echo "no existing image — first deploy, nothing to roll back to"
                    fi
                '''
            }
        }

        stage('Build') {
            steps {
                sh 'DOCKER_BUILDKIT=1 docker build -t "$IMAGE" .'
            }
        }

        stage('Deploy') {
            steps {
                dir("${STACK_DIR}") {
                    sh 'docker compose up -d --no-deps --force-recreate "$SERVICE"'
                }
            }
        }

        stage('Health check') {
            steps {
                script {
                    def healthy = sh(returnStatus: true, script: '''
                        for i in $(seq 1 30); do
                            if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
                                echo "healthy after ${i} attempt(s)"
                                exit 0
                            fi
                            sleep 5
                        done
                        exit 1
                    ''') == 0

                    if (!healthy) {
                        // The container has already been replaced, so production
                        // is broken right now. Put the previous image back before
                        // failing the build; a red pipeline over a working app
                        // beats a red pipeline over a dead one.
                        echo 'HEALTH CHECK FAILED — rolling back'
                        sh '''
                            if docker image inspect "$ROLLBACK" >/dev/null 2>&1; then
                                docker tag "$ROLLBACK" "$IMAGE"
                                cd "$STACK_DIR"
                                docker compose up -d --no-deps --force-recreate "$SERVICE"
                                for i in $(seq 1 24); do
                                    curl -fsS "$HEALTH_URL" >/dev/null 2>&1 && { echo "rolled back and healthy"; exit 0; }
                                    sleep 5
                                done
                                echo "ROLLBACK DID NOT COME BACK HEALTHY — needs a human"
                                exit 0
                            else
                                echo "no rollback image available — service is down"
                                exit 0
                            fi
                        '''
                        error 'Deploy failed health check; previous image restored'
                    }
                }
            }
        }

        stage('Reclaim disk') {
            steps {
                // Building from source on the box every deploy grows the build
                // cache without bound (6 GB reclaimable when this was written).
                // Bounded rather than emptied, so the next build still gets
                // useful layer reuse.
                sh '''
                    docker builder prune -f --max-used-space 4GB || true
                    docker image prune -f || true
                    df -h / | tail -1
                '''
            }
        }
    }

    post {
        success { echo "backend deployed: ${env.DEPLOY_SHA}" }
        failure { echo "backend deploy FAILED — check the Health check stage; a rollback may have run" }
    }
}
