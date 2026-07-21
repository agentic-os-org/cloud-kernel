pipeline {
    agent any

    environment {
        // ✅ 【修复】使用 Groovy 的 Elvis 运算符 (?:) 赋予默认值，这是绝对沙箱安全的做法
        REPO_URL = "${env.giteeRepositoryUrl ?: 'https://gitee.com/guoxuan-hu/cloud-kernel.git'}"
        PR_ID = "${env.giteePullRequestIid ?: ''}"
        SOURCE_BRANCH = "${env.giteePullRequestSourceBranch ?: 'devel-6.6'}"
        TARGET_BRANCH = "${env.giteePullRequestTargetBranch ?: 'devel-6.6'}"
        KERNEL_CONFIG = "defconfig"
    }

    stages {
        stage('Checkout PR Code') {
            steps {
                script {
                    // 清理工作区
                    cleanWs()
                    
                    sh """
                        echo "浅克隆 ${REPO_URL} 的 ${TARGET_BRANCH} 分支（深度1）..."
                        git clone --depth 1 --single-branch --branch "${TARGET_BRANCH}" "${REPO_URL}" .
                    """
                    
                    // 检查 PR_ID 是否存在且非空
                    if (env.PR_ID && env.PR_ID.trim()) {
                        sh """
                            echo "拉取 PR #${env.PR_ID} 的源分支 ${SOURCE_BRANCH}（深度1）..."
                            git fetch origin "${SOURCE_BRANCH}:pr_${env.PR_ID}_source" --depth=1
                            git checkout "pr_${env.PR_ID}_source"
                            
                            echo "尝试合并目标分支..."
                            git merge "origin/${TARGET_BRANCH}" --no-edit || true
                        """
                    } else {
                        echo "未检测到 PR ID（可能为 Push 或手动触发），跳过 PR 代码合并。"
                    }
                }
            }
        }

        stage('Configure Kernel') {
            steps {
                sh "make ${KERNEL_CONFIG}"
            }
        }

        stage('Patch规范检测') {
            steps {
                script {
                    if (env.PR_ID && env.PR_ID.trim()) {
                        sh """
                            echo "再次获取目标分支最新代码用于 diff..."
                            git fetch origin "${TARGET_BRANCH}" --depth=1
                            
                            echo "生成 patch 文件..."
                            git diff FETCH_HEAD..HEAD > "${WORKSPACE}/pr_${env.PR_ID}.patch"
                            
                            echo "执行 checkpatch.pl 检查..."
                            perl scripts/checkpatch.pl --no-tree --ignore EMAIL_SUBJECT,BRACES "${WORKSPACE}/pr_${env.PR_ID}.patch" || true
                        """
                    } else {
                        echo "非 PR 触发，跳过 Patch 规范检测。"
                    }
                }
            }
        }

        stage('Kernel Compilation') {
            steps {
                sh "make -j\$(nproc)"
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
            echo "流水线执行完毕，清理工作区..."
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