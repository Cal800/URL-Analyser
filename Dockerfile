FROM eclipse-temurin:17-jdk

WORKDIR /app

# Copy your source code and the PostgreSQL JDBC driver into the container
COPY Main.java .
COPY postgresql-42.7.13.jar .

# Compile the Java application with the JDBC driver in the classpath
RUN javac -cp postgresql-42.7.13.jar Main.java

# Run the compiled Java program
CMD ["java", "-cp", ".:postgresql-42.7.13.jar", "Main"]