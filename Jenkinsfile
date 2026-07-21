pipeline {
    agent any

    environment {
        // 从 Gitee 插件生成的环境变量中读取 PR 信息
        // 注意：这些变量仅在 Webhook 触发时才有值，手动构建时为空
        REPO_URL = "${env.giteeRepositoryUrl ?: 'https://gitee.com/guoxuan-hu/cloud-kernel.git'}"
        PR_ID = "${env.giteePullRequestIid ?: ''}"
        SOURCE_BRANCH = "${env.giteePullRequestSourceBranch ?: 'master'}"
        TARGET_BRANCH = "${env.giteePullRequestTargetBranch ?: 'devel-6.6'}"
        ACTION = "${env.giteeAction ?: ''}"
        
        // 编译配置
        KERNEL_CONFIG = "defconfig"
        MAKE_JOBS = "-j\$(nproc)"
    }

    stages {
        // 阶段1: 拉取 PR 代码
        stage('Checkout PR Code') {
            steps {
                script {
                    cleanWs()
                    
                    if (PR_ID && PR_ID.trim()) {
                        echo "检测到 PR #${PR_ID}，源分支: ${SOURCE_BRANCH}，目标分支: ${TARGET_BRANCH}"
                        
                        // 先克隆目标分支
                        checkout([
                            $class: 'GitSCM',
                            branches: [[name: "origin/${TARGET_BRANCH}"]],
                            userRemoteConfigs: [[url: REPO_URL]]
                        ])
                        
                        // 拉取源分支并 rebase 到目标分支（模拟 PR 合并后的状态）
                        sh """
                            git fetch origin ${SOURCE_BRANCH}:pr_${PR_ID}_source
                            git checkout pr_${PR_ID}_source
                            git rebase origin/${TARGET_BRANCH}
                        """
                    } else {
                        echo "未检测到 PR 信息，执行普通克隆 (分支: ${TARGET_BRANCH})"
                        checkout([
                            $class: 'GitSCM',
                            branches: [[name: "*/${TARGET_BRANCH}"]],
                            userRemoteConfigs: [[url: REPO_URL]]
                        ])
                    }
                }
            }
        }

        // 阶段2: 内核配置
        stage('Configure Kernel') {
            steps {
                sh """
                    make ${KERNEL_CONFIG}
                """
            }
        }

        // 阶段3: Patch 规范检测
        stage('Patch规范检测 (checkpatch.pl)') {
            steps {
                script {
                    if (PR_ID && PR_ID.trim()) {
                        sh """
                            git diff origin/${TARGET_BRANCH}..HEAD > ${WORKSPACE}/pr_${PR_ID}.patch
                            perl scripts/checkpatch.pl \
                                --no-tree \
                                --ignore EMAIL_SUBJECT,BRACES,FILE_PATH_CHANGES \
                                ${WORKSPACE}/pr_${PR_ID}.patch \
                                || true
                        """
                    } else {
                        echo "未检测到 PR，跳过 Patch 检测"
                    }
                }
            }
        }

        // 阶段4: 内核编译
        stage('Kernel Compilation') {
            steps {
                sh """
                    echo "开始编译内核 (使用 ${MAKE_JOBS})"
                    make ${MAKE_JOBS}
                """
            }
        }

        // 阶段5: 构建摘要
        stage('Build Summary') {
            steps {
                sh """
                    echo "=========================================="
                    echo "构建信息摘要:"
                    echo "  仓库: ${REPO_URL}"
                    echo "  分支: ${SOURCE_BRANCH} -> ${TARGET_BRANCH}"
                    echo "  PR #: ${PR_ID}"
                    echo "  事件: ${ACTION}"
                    echo "  架构: \$(uname -m)"
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
