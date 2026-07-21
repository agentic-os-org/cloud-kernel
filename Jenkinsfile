pipeline {
    agent any

    environment {
        // 从 Gitee Webhook 插件获取的环境变量
        REPO_URL = "${env.giteeRepositoryUrl ?: 'https://gitee.com/guoxuan-hu/cloud-kernel.git'}"
        PR_ID = "${env.giteePullRequestIid ?: ''}"
        SOURCE_BRANCH = "${env.giteePullRequestSourceBranch ?: 'devel-6.6'}"
        TARGET_BRANCH = "${env.giteePullRequestTargetBranch ?: 'devel-6.6'}"
        KERNEL_CONFIG = "defconfig"
        // 不再定义 MAKE_JOBS，直接在 sh 中使用
    }

    stages {
        stage('Checkout PR Code') {
            steps {
                script {
                    // 清空工作空间，避免旧文件干扰（但首次建议手动清理，后文会提）
                    cleanWs()
                    
                    // 用 git clone --depth 1 实现浅克隆，只拉取目标分支的最新一次提交
                    sh """
                        echo "浅克隆 ${REPO_URL} 的 ${TARGET_BRANCH} 分支（深度1）..."
                        git clone --depth 1 --single-branch --branch ${TARGET_BRANCH} ${REPO_URL} .
                    """
                    
                    // 如果是 PR 触发的，拉取源分支并合并（也使用浅克隆）
                    if (PR_ID && PR_ID.trim()) {
                        sh """
                            echo "拉取 PR #${PR_ID} 的源分支 ${SOURCE_BRANCH}（深度1）..."
                            git fetch origin ${SOURCE_BRANCH}:pr_${PR_ID}_source --depth=1
                            git checkout pr_${PR_ID}_source
                            git merge origin/${TARGET_BRANCH} --no-edit || true
                        """
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
                    if (PR_ID && PR_ID.trim()) {
                        // 在浅克隆下，需要先 fetch 目标分支的最新提交（用于 diff）
                        sh """
                            echo "获取目标分支最新快照以生成补丁..."
                            git fetch origin ${TARGET_BRANCH} --depth=1
                            # 比较 FETCH_HEAD（目标分支最新）和当前 HEAD（PR 代码）
                            git diff FETCH_HEAD..HEAD > ${WORKSPACE}/pr_${PR_ID}.patch
                            perl scripts/checkpatch.pl --no-tree --ignore EMAIL_SUBJECT,BRACES ${WORKSPACE}/pr_${PR_ID}.patch || true
                        """
                    } else {
                        echo "未检测到 PR，跳过 Patch 检测"
                    }
                }
            }
        }

        stage('Kernel Compilation') {
            steps {
                // 使用 nproc 动态获取 CPU 核心数，无需在 environment 中定义
                sh 'make -j$(nproc)'
            }
        }

        stage('Build Summary') {
            steps {
                sh """
                    echo "=========================================="
                    echo "构建信息:"
                    echo "  仓库: ${REPO_URL}"
                    echo "  PR #: ${PR_ID}"
                    echo "  分支: ${SOURCE_BRANCH} -> ${TARGET_BRANCH}"
                    echo "  源码大小: \$(du -sh . | cut -f1)"
                    echo "=========================================="
                """
            }
        }
    }

    post {
        // 总是清理工作空间（但编译产物可能很大，也可以保留，根据需求调整）
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
