pipeline {
    agent any

    // ── AuthSec backend — Hetzner single-node deploy ──────────────────────────
    // Push to authsec-staging → GitHub webhook → this pipeline runs ON the VM
    // (jenkins.authsec.ai lives on 192.168.122.252). It pulls source into
    // /opt/authsec/src/authsec, builds the image from the Dockerfile, and
    // recreates the `backend` service via the /opt/authsec compose stack.
    // No registry, no Azure/AKS — the VM builds from source every time.
    environment {
        SERVICE_NAME  = 'authsec'
        STACK_DIR     = '/opt/authsec'
        SRC_DIR       = '/opt/authsec/src/authsec'
        IMAGE         = 'authsec-backend:latest'
        DEPLOY_BRANCH = 'authsec-staging'
        HEALTH_URL    = 'https://app.authsec.ai/authsec/uflow/health'
    }

    triggers {
        githubPush()
    }

    options {
        buildDiscarder logRotator(artifactNumToKeepStr: '10', numToKeepStr: '10')
    }

    stages {
        stage('Pull source') {
            steps {
                sh """
                    cd ${SRC_DIR}
                    git fetch origin ${DEPLOY_BRANCH}
                    git reset --hard origin/${DEPLOY_BRANCH}
                    git log --oneline -1
                """
            }
        }

        stage('Build image') {
            steps {
                sh """
                    cd ${STACK_DIR}
                    DOCKER_BUILDKIT=1 docker compose build backend
                """
            }
        }

        stage('Deploy') {
            steps {
                sh """
                    cd ${STACK_DIR}
                    docker compose up -d --no-deps --force-recreate backend
                """
            }
        }

        stage('Health check') {
            steps {
                sh "curl -fsS --retry 12 --retry-delay 6 --retry-all-errors ${HEALTH_URL}"
            }
        }

        stage('Prune dangling images') {
            steps {
                sh "docker image prune -f || true"
            }
        }
    }

    post {
        success { echo "Deployed ${SERVICE_NAME} (${IMAGE}) to app.authsec.ai" }
        failure { echo "Deploy FAILED for ${SERVICE_NAME} — check build/compose logs on the VM (${STACK_DIR})" }
    }
}
