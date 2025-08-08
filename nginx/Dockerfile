FROM nginx:alpine

COPY ./conf/nginx.conf /etc/nginx/nginx.conf
COPY ./conf/gateway_only.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 443
