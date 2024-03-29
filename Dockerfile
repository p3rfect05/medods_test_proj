FROM alpine:latest
RUN mkdir /app

COPY ./tokenAPI /app

# Run the server executable
CMD [ "/app/tokenAPI" ]