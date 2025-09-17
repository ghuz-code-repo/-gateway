FROM nginx:alpine

COPY ./conf/nginx.conf /etc/nginx/nginx.conf
COPY ./conf/default.conf /etc/nginx/conf.d/default.conf
COPY ./html/favicon.ico /usr/share/nginx/html/favicon.ico
COPY ./html/favicon.svg /usr/share/nginx/html/favicon.svg
COPY ./html/404.html /usr/share/nginx/html/404.html

EXPOSE 80 443
