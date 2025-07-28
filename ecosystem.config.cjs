module.exports = {
  apps: [
    {
      name: 'vulnshop-backend',
      script: 'backend/server.js',
      cwd: '/var/www/vulnshop',
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
        PORT: 3001
      },
      env_development: {
        NODE_ENV: 'development',
        PORT: 3001
      },
      log_file: '/var/log/pm2/vulnshop-backend.log',
      error_file: '/var/log/pm2/vulnshop-backend-error.log',
      out_file: '/var/log/pm2/vulnshop-backend-out.log',
      pid_file: '/var/run/pm2/vulnshop-backend.pid',
      restart_delay: 4000,
      max_restarts: 10,
      min_uptime: '10s',
      kill_timeout: 1600
    }
  ]
}
