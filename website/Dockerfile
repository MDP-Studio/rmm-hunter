FROM nginx:1.27-alpine

COPY website/index.html /usr/share/nginx/html/index.html
COPY website/styles.css /usr/share/nginx/html/styles.css
COPY website/script.js /usr/share/nginx/html/script.js
COPY website/robots.txt /usr/share/nginx/html/robots.txt
COPY website/sitemap.xml /usr/share/nginx/html/sitemap.xml
COPY website/assets/ /usr/share/nginx/html/assets/
COPY website/nginx.conf /etc/nginx/conf.d/default.conf
