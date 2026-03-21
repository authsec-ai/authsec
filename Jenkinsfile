pipeline {
    agent any

    environment {
        // --- 1. GLOBAL CONFIGURATION (Edit this per service) ---
        SERVICE_NAME = 'authsec'  
        GITHUB_REPO = 'https://github.com/authsec-ai/authsec.git'
        
        // --- 2. STATIC VARIABLES (Do not edit until and unless you need to) ---
        DOCKER_REGISTRY = 'docker-repo.authsec.ai'
        DOCKER_REGISTRY_PUBLIC = 'docker-repo-public.authsec.ai'
        DOCKER_REGISTRY_CREDENTIALS = credentials('authsec-repo')
        DOCKER_PUBLIC_CREDENTIALS = credentials('authsec-public-repo')
        
        // Azure Credentials
        AZURE_CLIENT_ID = credentials('clientid')  
        AZURE_CLIENT_SECRET = credentials('secretid')
        AZURE_TENANT_ID = credentials('tenantid')
        
        AZURE_SUBSCRIPTION_ID_SEC = credentials('subscriptionIdauthsec')
        AKS_CLUSTER_SEC = 'authsec'
        RESOURCE_GROUP_SEC = 'Authnull'
        
        AZURE_SUBSCRIPTION_ID = credentials('subscriptionId')
        AKS_CLUSTER = 'authnull-v2'
        RESOURCE_GROUP = 'azure-k8s'
        
        
        // // --- 3. DYNAMIC VARIABLES (Calculated automatically in Initialize stage) ---
        // K8S_NAMESPACE = ''
        // DOCKER_IMAGE = ''
        // DOCKER_IMAGE_PUBLIC = ''
        // APP_LABEL = '' 
        // IS_PROD_BRANCH = 'false'
    }

    triggers {
        githubPush()
    }

    options {
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '10', daysToKeepStr: '', numToKeepStr: '10')
    }

    stages {
        // --- STAGE: CONFIGURE ENVIRONMENT ---
        stage('Initialize Environment') {
            steps {
                script {
                    echo "Current Branch: ${env.BRANCH_NAME}"
                    
                    // CHECK: Is this the production branch?
                    // Update 'authsec-prod' below if your production branch name is different
                    if (env.BRANCH_NAME == 'prod' || env.BRANCH_NAME == 'production') {
                        echo "Configuring for PRODUCTION environment..."
                        env.IS_PROD_BRANCH = 'true'
                        env.AKS_ENV = 'authsec'
                        
                        env.K8S_NAMESPACE = 'authsec-prod'
                        env.APP_LABEL = "prod-${SERVICE_NAME}"
                        
                        // Production uses specific tag
                        env.DOCKER_IMAGE = "${env.DOCKER_REGISTRY}/${SERVICE_NAME}:production"
                        env.DOCKER_IMAGE_PUBLIC = "${env.DOCKER_REGISTRY_PUBLIC}/${SERVICE_NAME}:1.0.0" 
                        
                    } else if (env.BRANCH_NAME == 'dev' || env.BRANCH_NAME == 'development') {
                        echo "Configuring for DEVELOPMENT environment..."
                        env.IS_PROD_BRANCH = 'false'
                        env.AKS_ENV = 'authsec'
                        
                        // Assuming you have a dev namespace. Change 'authsec-dev' if different.
                        env.K8S_NAMESPACE = 'authsec-dev'
                        env.APP_LABEL = "dev2-${SERVICE_NAME}"
                        
                        // Dev images get unique tags so they don't overwrite prod
                        env.DOCKER_IMAGE = "${env.DOCKER_REGISTRY}/${SERVICE_NAME}:development"
                        env.DOCKER_IMAGE_PUBLIC = "" // Not used in dev

                    } else if (env.BRANCH_NAME == 'staging' || env.BRANCH_NAME == 'develop') {
                        echo "Configuring for STAGING environment..."
                        env.IS_PROD_BRANCH = 'false'
                        env.AKS_ENV = 'authsec'
                        
                        // Assuming you have a staging namespace. Change 'authsec-stage' if different.
                        env.K8S_NAMESPACE = 'authsec-staging'
                        env.APP_LABEL = "stage-${SERVICE_NAME}"
                        
                        // Dev images get unique tags so they don't overwrite prod
                        env.DOCKER_IMAGE = "${env.DOCKER_REGISTRY}/${SERVICE_NAME}:stage"
                        env.DOCKER_IMAGE_PUBLIC = "" // Not used in staging

                    } else if (env.BRANCH_NAME == 'main' || env.BRANCH_NAME == 'master') {
                        echo "Configuring for CURRENT PROD environment..."
                        env.IS_PROD_BRANCH = 'false'
                        env.AKS_ENV = 'authnull'
                        
                        // Assuming you have a authsec namespace. Change 'authsec' if different.
                        env.K8S_NAMESPACE = 'authsec'
                        env.APP_LABEL = "dev-${SERVICE_NAME}"
                        
                        // Dev images get unique tags so they don't overwrite prod
                        env.DOCKER_IMAGE = "${env.DOCKER_REGISTRY}/${SERVICE_NAME}:latest"
                        env.DOCKER_IMAGE_PUBLIC = "" // Not used in current prod
                        
                    } else {
                        echo "No matching environment configuration found for branch: ${env.BRANCH_NAME}"
                        error "BUILD FAILED: Unrecognized branch for deployment."
                    }
                }
            }
        }

        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('OSV Scanner - Source Code') {
            steps {
                    script {
                        def scanExit = sh(
                            script: 'osv-scanner scan --recursive --output osv-source-scan.json .',
                            returnStatus: true
                        )
                        
                        if (scanExit != 0) {
                            echo "WARNING: OSV Scanner found vulnerabilities in source code (exit code: ${scanExit})"
                            echo "Continuing pipeline to evaluate severity..."
                        } else {
                            echo "SUCCESS: No vulnerabilities found in source code"
                        }
                    }
                }
            }
        
            stage('OSV Scanner - Docker Image Scan') {
            steps {
                script {
                    def scanExit = sh(
                        script: "osv-scanner scan image ${env.DOCKER_IMAGE} --output osv-docker-scan.json",
                        returnStatus: true
                    )
                    if (scanExit != 0) {
                        echo "WARNING: OSV Scanner found vulnerabilities"
                    } else {
                        echo "SUCCESS: No vulnerabilities found by OSV Scanner"
                    }
                }
            }
        }
        
        stage('Vulnerability Quality Gate') {
            steps {
                script {
                    def criticalCount = 0
                    def highCount = 0
                    if (fileExists('osv-docker-scan.json')) {
                        def jsonContent = readFile('osv-docker-scan.json')
                        criticalCount = jsonContent.count('"severity":"CRITICAL"')
                        highCount = jsonContent.count('"severity":"HIGH"')
                        echo "Parsed: Critical=${criticalCount}, High=${highCount}"
                    } 
                    
                    // Hard Fail on Critical
                    if (criticalCount > 0) {
                        error "BUILD FAILED: ${criticalCount} CRITICAL vulnerabilities found."
                    }
                    if (highCount > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "WARNING: ${highCount} HIGH severity vulnerabilities found"
                    }
                    currentBuild.description = "Branch: ${env.BRANCH_NAME} | Vulns: C${criticalCount} H${highCount}"
                }
            }
        }
    }   
    post {
        always {
            archiveArtifacts artifacts: 'osv-*.json', fingerprint: true

            sh '''
                echo "=== OSV Security Scan Report ===" > security-summary.txt
                echo "Scan completed: $(date)" >> security-summary.txt
                echo "Service: ${SERVICE_NAME}" >> security-summary.txt
                echo "Environment: ${BRANCH_NAME}" >> security-summary.txt
            '''
        }

        success {
            echo "SUCCESS: Build completed successfully for ${env.SERVICE_NAME} on ${env.BRANCH_NAME}"
        }

        failure {
            echo "FAILURE: Build failed"
        }
    }
}
