# Nidas
온라인 신발 쇼핑몰 서비스

# 실행 방법
## IDE 실행법
IDE에서 프로젝트로 불러온 후 메이븐 컴파일을 수행하고 NidasApplication.class를 실행합니다.

## 콘솔 실행법
```
mvnw clean compile package
```
```
java -jar target/*.jar
```

# DB 설정
PostgreSQL을 설치하고 psql로 접속해서 아래 명령어를 실행합니다.

```sql
CREATE DATABASE nidas;
CREATE USER testuser WITH ENCRYPTED PASSWORD 'testpass';
GRANT ALL PRIVILEGES ON DATABASE nidas TO testuser;
```

# 관리자 계정 생성
1. 회원가입 페이지에서 일반 계정을 생성합니다.
2. psql에 접속해서 아래 명령어를 실행합니다.

```sql
\c nidas
UPDATE account SET authority = 'ROLE_ADMIN' WHERE email = '생성한 계정 이메일';
```

3. 변경사항을 반영하기 위해 로그아웃하고 다시 로그인합니다.

# SMTP 설정
앱 패스워드를 발급받아 `application-dev.properties`에 이메일과 앱 패스워드를 입력합니다.
