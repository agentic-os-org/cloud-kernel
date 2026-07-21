pipeline {
    agent any

    environment {
        // 使用 getProperty 方式，避免变量不存在时抛异常
        REPO_URL = "${env.getProperty('giteeRepositoryUrl', 'https://gitee.com/guoxuan-hu/cloud-kernel.git')}"
        PR_ID = "${env.getProperty('giteePullRequestIid', '')}"
        SOURCE_BRANCH = "${env.getProperty('giteePullRequestSourceBranch', 'devel-6.6')}"
        TARGET_BRANCH = "${env.getProperty('giteePullRequestTargetBranch', 'devel-6.6')}"
        KERNEL_CONFIG = "defconfig"
    }

    stages {
        stage('Checkout PR Code') {
            steps {
                script {
                    cleanWs()
                    sh """
                        echo "浅克隆 ${REPO_URL} 的 ${TARGET_BRANCH} 分支（深度1）..."
                        git clone --depth 1 --single-branch --branch ${TARGET_BRANCH} ${REPO_URL} .
                    """
                    // 注意：这里用 env.PR_ID 而不是 PR_ID，确保从环境变量中读取
                    if (env.PR_ID && env.PR_ID.trim()) {
                        sh """
                            echo "拉取 PR #${env.PR_ID} 的源分支 ${SOURCE_BRANCH}（深度1）..."
                            git fetch origin ${SOURCE_BRANCH}:pr_${env.PR_ID}_source --depth=1
                            git checkout pr_${env.PR_ID}_source
                            git merge origin/${TARGET_BRANCH} --no-edit || true
                        """
                    } else {
                        echo "未检测到 PR（Push 或手动触发），跳过 Patch 检测"
                    }
                }
            }
        }

        stage('Configure Kernel') {
            steps {
                sh 'make ${KERNEL_CONFIG}'
            }
        }

        stage('Patch规范检测') {
            steps {
                script {
                    if (env.PR_ID && env.PR_ID.trim()) {
                        sh """
                            git fetch origin ${TARGET_BRANCH} --depth=1
                            git diff FETCH_HEAD..HEAD > ${WORKSPACE}/pr_${env.PR_ID}.patch
                            perl scripts/checkpatch.pl --no-tree --ignore EMAIL_SUBJECT,BRACES ${WORKSPACE}/pr_${env.PR_ID}.patch || true
                        """
                    } else {
                        echo "未检测到 PR，跳过 Patch 检测"
                    }
                }
            }
        }

        stage('Kernel Compilation') {
            steps {
                sh 'make -j$(nproc)'
            }
        }

        stage('Build Summary') {
            steps {
                sh """
                    echo "=========================================="
                    echo "构建信息:"
                    echo "  仓库: ${REPO_URL}"
                    echo "  PR #: ${env.PR_ID}"
                    echo "  分支: ${SOURCE_BRANCH} -> ${TARGET_BRANCH}"
                    echo "  源码大小: \$(du -sh . | cut -f1)"
                    echo "=========================================="
                """
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo "✅ Pipeline 执行成功！"
        }
        failure {
            echo "❌ Pipeline 执行失败，请查看日志。"
        }
    }
}
