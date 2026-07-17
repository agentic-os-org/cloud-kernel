pipeline {
    agent any

    stages {
        // 1. 拉取PR代码
        stage('Checkout PR Code') {
            steps {
                checkout([
                    // $class: 'GitSCM' 是必须的
                    $class: 'GitSCM',
                    branches: [[name: 'pull/${giteePullRequestIid}/MERGE']],
                    userRemoteConfigs: [[
                        url: 'https://gitee.com/guoxuan-hu/cloud-kernel.git', 
                        credentialsId: 'Gitee-Token'
                    ]],
                    // 重要：配置Refspec让Jenkins能拉取PR的合并状态
                    extensions: [[
                        $class: 'CloneOption', 
                        refspec: '+refs/pull/*/MERGE:refs/pull/*/MERGE'
                    ]]
                ])
            }
        }

        // 2. Patch规范检测
        stage('Patch规范检测') {
            steps {
                // 假设你的内核代码根目录有 scripts/checkpatch.pl 脚本
                // 注意：这里以检测最近一次提交为例，你也可以检测整个PR的变更
                sh 'scripts/checkpatch.pl -f --no-signoff --no-tree --terse HEAD~1..HEAD'
            }
        }

        // 3. 内核编译 (示例)
        stage('Kernel Compile') {
            steps {
                // 根据你的内核项目配置编译命令，例如：
                // sh 'make defconfig'
                // sh 'make -j$(nproc)'
                sh 'echo "Kernel compilation step - replace with actual commands"'
            }
        }
    }

    post {
        success {
            // 构建成功后，可以将状态回评到Gitee PR中
            // 这需要配置Gitee插件的构建后操作，或在脚本中使用Gitee API
            echo 'Pipeline succeeded!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}