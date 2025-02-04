FROM maven:3.9.9-eclipse-temurin-21-alpine AS builder

WORKDIR /builder

COPY pom.xml ./
COPY src ./src

RUN ["mvn", "clean", "package", "-Dmaven.test.skip=true"]

FROM eclipse-temurin:21.0.5_11-jdk-alpine AS runner

WORKDIR /runner

COPY --from=builder /builder/target/netology-cloud-storage-0.0.1-SNAPSHOT.jar /runner

EXPOSE 5050

ENTRYPOINT ["java", "-jar", "/runner/netology-cloud-storage-0.0.1-SNAPSHOT.jar"]
