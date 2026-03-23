// =============================================================================
// DevSecOps Pipeline - Bachelor 2026
// Automated Vulnerability Detection in CI/CD Process
// =============================================================================

pipeline {
    agent any

    environment {
        APP_NAME          = 'spring-boot-app'
        APP_VERSION       = "${BUILD_NUMBER}"
        DOCKER_REGISTRY   = 'localhost:5000'
        DOCKER_IMAGE      = "${DOCKER_REGISTRY}/${APP_NAME}"
        DOCKER_TAG        = "${APP_VERSION}"
        K8S_NAMESPACE     = 'devsecops-test'
        K8S_DEPLOYMENT    = 'spring-boot-app'
        SONAR_HOST        = 'http://localhost:9000'
        SONAR_PROJECT     = 'devsecops-prototype'
        TARGET_URL        = "http://spring-boot-app-service.devsecops-test.svc.cluster.local:8080"
        REPORTS_DIR       = 'reports'
        SECURITY_SCRIPT   = 'security/orchestrator/security_orchestrator.py'
        TRIAGE_SCRIPT     = 'security/triage/vulnerability_triage.py'
        REPORT_SCRIPT     = 'security/reporter/report_generator.py'
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 60, unit: 'MINUTES')
        timestamps()
    }

    stages {  
        stage('1 – Checkout') {
            steps {
                echo '>>> FULL checkout...'
                deleteDir()   // важно!
        
                git branch: 'main', 
                    url: 'https://github.com/doroGU-Ylitkam/DevSecOps-clean.git'
                
                sh 'ls -la security/orchestrator/'
            }
        }

        stage('2 – Build') {
            steps {
                echo '>>> Building Java Spring Boot application...'
                sh 'mvn clean package -DskipTests --batch-mode --no-transfer-progress'
            }
            post {
                success { archiveArtifacts artifacts: 'target/*.jar', fingerprint: true }
            }
        }

        stage('3 – Unit Tests') {
            steps {
                echo '>>> Running unit tests...'
                sh 'mvn test --batch-mode --no-transfer-progress'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'target/surefire-reports/*.xml'
                }
            }
        }

           stage('4 – SAST: SonarQube') {
                steps {
                    echo '>>> Running Static Application Security Testing (SonarQube)...'
                    sh 'echo "WORKSPACE=$(pwd)"'
                    sh 'ls -la security/orchestrator/ || echo "DIR NOT FOUND"'
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        sh '''
                            mvn sonar:sonar \
                                -Dsonar.projectKey=${SONAR_PROJECT} \
                                -Dsonar.host.url=http://host.docker.internal:9000 \
                                -Dsonar.login=${SONAR_TOKEN} \
                                --batch-mode --no-transfer-progress
                        '''
                        sh '''
                            docker run --rm \
                                -v $(pwd):/app \
                                python:3.11 \
                                python ${SECURITY_SCRIPT} \
                                    --tool sonarqube \
                                    --sonar-host http://host.docker.internal:9000 \
                                    --sonar-token $SONAR_TOKEN \
                                    --sonar-project devsecops-prototype \
                                    --output /app/${REPORTS_DIR}/sonarqube-report.json
                        '''
                    }
                }
                post {
                    always {
                        archiveArtifacts artifacts: "${REPORTS_DIR}/sonarqube-report.json",
                                         allowEmptyArchive: true
                    }
                }
            }

        stage('5 – Dependency Scanning: OWASP DC') {
            steps {
                echo '>>> Running OWASP Dependency-Check...'
                sh '''
                    mvn org.owasp:dependency-check-maven:check \
                        -Dformat=JSON \
                        -DoutputDirectory=${REPORTS_DIR} \
                        -DfailBuildOnCVSS=0 \
                        --batch-mode --no-transfer-progress || true

                    python3 ${SECURITY_SCRIPT} \
                        --tool dependency-check \
                        --input ${REPORTS_DIR}/dependency-check-report.json \
                        --output ${REPORTS_DIR}/dependency-check-normalized.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/dependency-check*.json", allowEmptyArchive: true
                    dependencyCheckPublisher pattern: "${REPORTS_DIR}/dependency-check-report.json"
                }
            }
        }

        stage('6 – Docker Build') {
            steps {
                echo '>>> Building Docker image...'
                sh '''
                    docker build \
                        -t ${DOCKER_IMAGE}:${DOCKER_TAG} \
                        -t ${DOCKER_IMAGE}:latest \
                        --label "build=${BUILD_NUMBER}" \
                        -f docker/Dockerfile .
                '''
            }
        }

        stage('7 – Container Scanning: Trivy') {
            steps {
                echo '>>> Scanning Docker image with Trivy...'
                sh '''
                    trivy image \
                        --format json \
                        --output ${REPORTS_DIR}/trivy-report.json \
                        --exit-code 0 \
                        --severity HIGH,CRITICAL \
                        --no-progress \
                        ${DOCKER_IMAGE}:${DOCKER_TAG}

                    python3 ${SECURITY_SCRIPT} \
                        --tool trivy \
                        --input ${REPORTS_DIR}/trivy-report.json \
                        --output ${REPORTS_DIR}/trivy-normalized.json
                '''
            }
            post {
                always { archiveArtifacts artifacts: "${REPORTS_DIR}/trivy*.json", allowEmptyArchive: true }
            }
        }

        stage('8 – Deploy to Test Env') {
            steps {
                echo '>>> Simulating Kubernetes deployment...'
                sh '''
                    echo "Applying deployment.yaml"
                    echo "Applying service.yaml"
                    echo "Rollout successful"
                '''
            }
        }

        stage('9 – DAST: OWASP ZAP') {
            steps {
                echo '>>> Running Dynamic Application Security Testing (OWASP ZAP)...'
                sh '''
                    docker run -d --name zap-daemon --network host \
                        -v $(pwd)/${REPORTS_DIR}:/zap/wrk \
                        owasp/zap2docker-stable \
                        zap.sh -daemon -host 0.0.0.0 -port 8090 \
                            -config api.addrs.addr.name=.* \
                            -config api.addrs.addr.regex=true \
                            -config api.disablekey=true
                    sleep 15

                    python3 ${SECURITY_SCRIPT} \
                        --tool zap \
                        --zap-host http://localhost:8090 \
                        --target-url ${TARGET_URL} \
                        --output ${REPORTS_DIR}/zap-report.json
                '''
            }
            post {
                always {
                    sh 'docker rm -f zap-daemon || true'
                    archiveArtifacts artifacts: "${REPORTS_DIR}/zap-report.json", allowEmptyArchive: true
                }
            }
        }

        stage('10 – Vulnerability Triage') {
            steps {
                echo '>>> Merging reports and running automated triage...'
                sh '''
                    python3 security/merger/report_merger.py \
                        --inputs \
                            ${REPORTS_DIR}/sonarqube-report.json \
                            ${REPORTS_DIR}/dependency-check-normalized.json \
                            ${REPORTS_DIR}/trivy-normalized.json \
                            ${REPORTS_DIR}/zap-report.json \
                        --output ${REPORTS_DIR}/merged-vulnerabilities.json

                    python3 ${TRIAGE_SCRIPT} \
                        --input  ${REPORTS_DIR}/merged-vulnerabilities.json \
                        --output ${REPORTS_DIR}/triaged-vulnerabilities.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/merged*.json,${REPORTS_DIR}/triaged*.json",
                                     allowEmptyArchive: true
                }
            }
        }

        stage('11 – Generate Final Report') {
            steps {
                echo '>>> Generating unified vulnerability report...'
                sh '''
                    python3 ${REPORT_SCRIPT} \
                        --input   ${REPORTS_DIR}/triaged-vulnerabilities.json \
                        --output  ${REPORTS_DIR}/final-vulnerability-report.html \
                        --json    ${REPORTS_DIR}/final-vulnerability-report.json \
                        --build   ${BUILD_NUMBER} \
                        --app     ${APP_NAME} \
                        --version ${APP_VERSION}
                '''
            }
            post {
                always {
                    publishHTML(target: [
                        allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                        reportDir: "${REPORTS_DIR}", reportFiles: 'final-vulnerability-report.html',
                        reportName: 'Security Vulnerability Report'
                    ])
                    archiveArtifacts artifacts: "${REPORTS_DIR}/final-vulnerability-report.*",
                                     allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            echo '>>> Archiving all security artifacts...'
            archiveArtifacts artifacts: "${REPORTS_DIR}/**/*", allowEmptyArchive: true
        }
        success {
            echo '>>> Pipeline SUCCEEDED.'
        }
        failure {
            echo '>>> Pipeline FAILED – critical vulnerabilities detected.'
        }
        cleanup {
            sh 'kubectl delete deployment/${K8S_DEPLOYMENT} --namespace=${K8S_NAMESPACE} --ignore-not-found=true || true'
            cleanWs()
        }
    }
}
