module.exports = {
  apps: [
    {
      name: 'zkanalyzer-main',
      script: './target/release/zkanalyzer',
      args: '--config config/production.yaml',
      cwd: '/home/ubuntu/Sandeep/projects/ZKanalyser',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '10G',
      env: {
        NODE_ENV: 'production',
        RUST_LOG: 'info',
        RUST_BACKTRACE: '1',
        ZKANALYZER_ENV: 'production'
      },
      env_production: {
        NODE_ENV: 'production',
        RUST_LOG: 'info,zkanalyzer=debug',
        RUST_BACKTRACE: 'full',
        ZKANALYZER_ENV: 'production'
      },
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      error_file: '/home/ubuntu/.zkanalyzer/logs/pm2-error.log',
      out_file: '/home/ubuntu/.zkanalyzer/logs/pm2-out.log',
      log_file: '/home/ubuntu/.zkanalyzer/logs/pm2-combined.log',
      time: true,
      merge_logs: true,
      max_restarts: 10,
      min_uptime: '10s',
      restart_delay: 4000,
      kill_timeout: 5000,
      listen_timeout: 3000,
      shutdown_with_message: true,
      wait_ready: true,
      health_check_grace_period: 3000,
      health_check_fatal_exceptions: true
    },
    {
      name: 'zkanalyzer-api',
      script: './target/release/zkanalyzer',
      args: '--config config/production.yaml --api-only',
      cwd: '/home/ubuntu/Sandeep/projects/ZKanalyser',
      instances: 2,
      exec_mode: 'cluster',
      autorestart: true,
      watch: false,
      max_memory_restart: '2G',
      env: {
        NODE_ENV: 'production',
        RUST_LOG: 'info',
        ZKANALYZER_ENV: 'production',
        ZKANALYZER_PORT: '9102'
      },
      env_production: {
        NODE_ENV: 'production',
        RUST_LOG: 'info,zkanalyzer=debug',
        ZKANALYZER_ENV: 'production',
        ZKANALYZER_PORT: '9102'
      },
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      error_file: '/home/ubuntu/.zkanalyzer/logs/api-error.log',
      out_file: '/home/ubuntu/.zkanalyzer/logs/api-out.log',
      log_file: '/home/ubuntu/.zkanalyzer/logs/api-combined.log',
      time: true,
      merge_logs: true,
      max_restarts: 15,
      min_uptime: '5s',
      restart_delay: 2000,
      kill_timeout: 3000,
      listen_timeout: 2000
    },
    {
      name: 'zkanalyzer-web',
      script: './target/release/zkanalyzer',
      args: '--config config/production.yaml --web-only',
      cwd: '/home/ubuntu/Sandeep/projects/ZKanalyser',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        RUST_LOG: 'info',
        ZKANALYZER_ENV: 'production',
        ZKANALYZER_WEB_PORT: '8080'
      },
      env_production: {
        NODE_ENV: 'production',
        RUST_LOG: 'info,zkanalyzer=debug',
        ZKANALYZER_ENV: 'production',
        ZKANALYZER_WEB_PORT: '8080'
      },
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      error_file: '/home/ubuntu/.zkanalyzer/logs/web-error.log',
      out_file: '/home/ubuntu/.zkanalyzer/logs/web-out.log',
      log_file: '/home/ubuntu/.zkanalyzer/logs/web-combined.log',
      time: true,
      merge_logs: true,
      max_restarts: 10,
      min_uptime: '5s',
      restart_delay: 2000
    },
    {
      name: 'zkanalyzer-metrics',
      script: './target/release/zkanalyzer',
      args: '--config config/production.yaml --metrics-only',
      cwd: '/home/ubuntu/Sandeep/projects/ZKanalyser',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        RUST_LOG: 'info',
        ZKANALYZER_ENV: 'production',
        ZKANALYZER_METRICS_PORT: '9090'
      },
      env_production: {
        NODE_ENV: 'production',
        RUST_LOG: 'info,zkanalyzer=debug',
        ZKANALYZER_ENV: 'production',
        ZKANALYZER_METRICS_PORT: '9090'
      },
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      error_file: '/home/ubuntu/.zkanalyzer/logs/metrics-error.log',
      out_file: '/home/ubuntu/.zkanalyzer/logs/metrics-out.log',
      log_file: '/home/ubuntu/.zkanalyzer/logs/metrics-combined.log',
      time: true,
      merge_logs: true,
      max_restarts: 5,
      min_uptime: '10s',
      restart_delay: 5000
    }
  ],

  deploy: {
    production: {
      user: 'ubuntu',
      host: '3.111.22.56',
      ref: 'origin/main',
      repo: 'https://github.com/MrDecryptDecipher/ZKanalyser.git',
      path: '/home/ubuntu/Sandeep/projects/ZKanalyser',
      'pre-deploy-local': '',
      'post-deploy': 'cargo build --release && pm2 reload ecosystem.config.js --env production',
      'pre-setup': 'sudo apt-get update && sudo apt-get install -y build-essential pkg-config libssl-dev',
      'post-setup': 'mkdir -p /home/ubuntu/.zkanalyzer/logs && mkdir -p /home/ubuntu/.zkanalyzer/data',
      env: {
        NODE_ENV: 'production',
        RUST_LOG: 'info'
      }
    }
  }
};
