# Stage 1: Build
FROM maven:3.8.4-openjdk-17 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:17-jre AS runtime
WORKDIR /app
COPY --from=build /app/target/auth-gateway-service-0.0.1-SNAPSHOT.jar /app/auth-gateway-service.jar
EXPOSE 8464
CMD ["java", "-jar", "auth-gateway-service.jar"]
