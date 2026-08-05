pipeline {
    agent any

    environment {
        SERVICE_NAME = 'authsec'  
        GITHUB_REPO = 'https://github.com/authsec-ai/authsec.git'
        GITHUB_BRANCH = 'authsec-staging'
        DOCKER_REGISTRY = 'docker-repo-public.authnull.com'
        DOCKER_REGISTRY_CREDENTIALS = credentials('docker-repo-public')
        TAG = 'stage'
        DOCKER_IMAGE = "docker-repo-public.authnull.com/authsec:${TAG}"

        
    }

    triggers {
        githubPush()
    }

    options {
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '10', daysToKeepStr: '', numToKeepStr: '10')
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_SHA = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
                    env.IMAGE_TAG = "${env.BRANCH_NAME}-${env.BUILD_NUMBER}-${env.GIT_SHA}".replaceAll("[^A-Za-z0-9_.-]", "-")
                    env.DOCKER_IMAGE_IMMUTABLE = "${env.DOCKER_REGISTRY}/${env.SERVICE_NAME}:${env.IMAGE_TAG}"
                }
            }
        }

        stage('Build Public Image') {
            steps {
                sh """
                    echo "Building PUBLIC image: ${DOCKER_IMAGE}"
                    DOCKER_BUILDKIT=1 docker build -t ${DOCKER_IMAGE} .
                """
            }
        }

        stage('Login to Docker Artifactory') {
            steps {
                sh "echo ${DOCKER_REGISTRY_CREDENTIALS_PSW} | docker login ${DOCKER_REGISTRY} -u ${DOCKER_REGISTRY_CREDENTIALS_USR} --password-stdin"
            }
        }

        stage('Push Docker Image') {
            steps {
                sh """
                    docker push ${env.DOCKER_IMAGE}
                """
            }
        }

        stage('Logout from Docker Artifactory') {
            steps {
                sh "docker logout ${env.DOCKER_REGISTRY}"
            }
        }

        stage('Remove Docker Image') {
            steps {
                sh "docker rmi ${env.DOCKER_IMAGE} || true"
            }
        }
    }
}
