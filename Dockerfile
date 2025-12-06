# Используем образ с JDK 17
FROM eclipse-temurin:21-jdk-alpine

# Метаданные
LABEL maintainer="compliance-auth-service"
LABEL version="1.0.0"

# Рабочая директория
WORKDIR /app

# Копируем собранный jar файл
COPY target/compliance-auth-service-0.0.1-SNAPSHOT.jar app.jar

# Создаем пользователя для безопасности
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Порт приложения
EXPOSE 9091

# Запуск приложения
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
