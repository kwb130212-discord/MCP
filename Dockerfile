FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
RUN printf 'server {\n    listen 10000;\n    server_name _;\n    root /usr/share/nginx/html;\n    index index.html;\n    location / { try_files $uri $uri/ =404; }\n    location = /healthz { access_log off; return 200 "ok"; add_header Content-Type text/plain; }\n}\n' > /etc/nginx/conf.d/default.conf
EXPOSE 10000
