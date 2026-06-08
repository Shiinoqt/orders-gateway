FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY target/spring-gateway-0.0.1-SNAPSHOT.jar gateway.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "gateway.jar"]