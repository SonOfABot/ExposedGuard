FROM nginx:alpine
COPY vulnerable /usr/share/nginx/html/vulnerable
COPY clean /usr/share/nginx/html/clean
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Rename the dotfile fixtures into place (kept as "dotenv*" in the repo
# so editors/tools don't treat them as real secret files)
RUN mv /usr/share/nginx/html/vulnerable/dotenv /usr/share/nginx/html/vulnerable/.env \
    && mv /usr/share/nginx/html/vulnerable/dotenv.production /usr/share/nginx/html/vulnerable/.env.production
EXPOSE 8080 8081
