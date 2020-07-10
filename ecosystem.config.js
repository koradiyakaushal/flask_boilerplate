module.exports = {
    apps : [{
      name: 'Flask-App',
      script: 'pipenv run python',
      args: 'api/run.py',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      interpreter:'/var/lib/jenkins/workspace/test 2/venv/bin/python'
    }]
  };
