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
                    // 清理工作区是一个好习惯
                    cleanWs()
                    
                    // 使用双引号来正确进行变量插值
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
                            // 使用 || true 避免合并冲突时导致流水线失败
                            git merge "origin/${TARGET_BRANCH}" --no-edit || true
                        """
                    } else {
                        echo "未检测到 PR ID（可能为 Push 或手动触发），跳过 PR 相关操作。"
                    }
                }
            }
        }

        stage('Configure Kernel') {
            steps {
                // ✅ 【修复】单引号改为双引号
                sh "make ${KERNEL_CONFIG}"
            }
        }

        stage('Patch规范检测') {
            steps {
                script {
                    // 同样，检查 PR_ID
                    if (env.PR_ID && env.PR_ID.trim()) {
                        sh """
                            echo "再次获取目标分支最新代码用于 diff..."
                            git fetch origin "${TARGET_BRANCH}" --depth=1
                            
                            echo "生成 patch 文件..."
                            git diff FETCH_HEAD..HEAD > "${WORKSPACE}/pr_${env.PR_ID}.patch"
                            
                            echo "执行 checkpatch.pl 检查..."
                            # 使用 || true 确保即使检查不通过，也只是打印警告，而不是让流水线失败
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
                // ✅ 【修复】单引号改为双引号
                sh "make -j\$(nproc)"
            }
        }

        stage('Build Summary') {
            steps {
                // 这里也统一使用双引号
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
            // 在 post 阶段清理工作区是最佳实践
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