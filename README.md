# 🛡️ NestJS Cognito Auth App

Here’s a complete `README.md` file that’ll make your NestJS + AWS Cognito + Google OAuth + RBAC project
---

## Table of Contents

1. [🛡️ NestJS Cognito Auth App](#-nestjs-cognito-auth-app)
2. [✨ Features](#-features)
3. [📁 Project Structure](#-project-structure)
4. [🧪 Tech Stack](#-tech-stack)
5. [🛠 Installation](#-installation)
   - [1. Clone the repo](#1-clone-the-repo)
   - [2. Install dependencies](#2-install-dependencies)
   - [3. Environment Variables](#3-environment-variables)
6. [🚀 Run the app](#-run-the-app)
7. [🔐 Google OAuth Flow](#-google-oauth-flow)
8. [📚 Swagger API Docs](#-swagger-api-docs)
9. [✏️ User CRUD API](#-user-crud-api)
10. [👑 RBAC Example](#-rbac-example)
11. [🧠 To Do / Next Steps](#-to-do--next-steps)
12. [🚀 Option 1: Deploy to AWS EC2](#-option-1-deploy-to-aws-ec2)
   - [🧰 Requirements](#-requirements)
   - [🔧 Step-by-Step: EC2 Deployment](#-step-by-step-ec2-deployment)
13. [🛠 Option 2: Deploy to AWS Lambda (Serverless)](#-option-2-deploy-to-aws-lambda-serverless)
   - [🔧 Step-by-Step: Lambda Deployment via Serverless Framework](#-step-by-step-lambda-deployment-via-serverless-framework)
14. [📜 `ec2-bootstrap-ubuntu-nginx.sh`](#-ec2-bootstrap-ubuntu-nginx-sh)
15. [🌟 What’s Next?](#-whats-next)
16. [✅ Updated Ubuntu EC2 Bootstrap Script Using NVM](#-updated-ubuntu-ec2-bootstrap-script-using-nvm)
17. [💡 Pro Tips](#-pro-tips)

---



---

```md
# 🛡️ NestJS Cognito Auth App

A full-featured **NestJS** application for **AWS Cognito** user management with **Google OAuth2 login** and **Role-Based Access Control (RBAC)**. Includes complete **CRUD functionality** and **Swagger API documentation**.

---

## ✨ Features

- 🔐 AWS Cognito user authentication
- 🌐 Google OAuth2 login with Passport strategy
- 👑 Role-Based Access Control (RBAC)
- ✏️ User CRUD operations
- 🧪 Swagger API documentation
- 🧠 In-memory user store (can be swapped with database)

---

## 📁 Project Structure

```bash
src/
├── auth/
│   ├── auth.controller.ts
│   ├── auth.module.ts
│   ├── auth.service.ts
│   └── strategies/
│       └── google.strategy.ts
├── user/
│   ├── user.controller.ts
│   ├── user.module.ts
│   ├── user.service.ts
│   └── dto/
│       ├── create-user.dto.ts
│       └── update-user.dto.ts
├── roles/
│   ├── roles.guard.ts
│   ├── roles.decorator.ts
│   └── roles.module.ts
├── main.ts
```

---

## 🧪 Tech Stack

- [NestJS](https://nestjs.com/)
- [Passport.js](http://www.passportjs.org/)
- [AWS Cognito](https://aws.amazon.com/cognito/)
- [Google OAuth2](https://developers.google.com/identity)
- [Swagger](https://swagger.io/)
- [TypeScript](https://www.typescriptlang.org/)

---

## 🛠 Installation

### 1. Clone the repo

```bash
git clone https://github.com/evillan0315/cognito-auth-app.git
cd cognito-auth-app
```

### 2. Install dependencies

```bash
npm install
```

### 3. Environment Variables

Create a `.env` file in the root directory:

```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
AWS_REGION=your_aws_region
AWS_USER_POOL_ID=your_user_pool_id
AWS_CLIENT_ID=your_cognito_client_id
API_URL=http://localhost:3000
JWT_SECRET=AKIASIVGLCJ276APEARY
SESSION_SECRET=AKIASIVGLCJ276APEARY
PORT=3000
ENV=development
DATABASE_URL=
```

---

## 🚀 Run the app

```bash
npm run start:dev
```

---

## 🔐 Google OAuth Flow

1. Visit: `http://localhost:3000/auth/google`
2. Authorize via Google
3. You’ll be redirected to `http://localhost:3000/auth/google/callback` with user info

---

## 📚 Swagger API Docs

Visit: `http://localhost:3000/api`

Includes full API documentation with input/output schemas for all endpoints.

---

## ✏️ User CRUD API

| Method | Endpoint       | Description             |
|--------|----------------|-------------------------|
| GET    | /users         | Get all users           |
| GET    | /users/:id     | Get user by ID          |
| POST   | /users         | Create a new user       |
| PUT    | /users/:id     | Update user by ID       |
| DELETE | /users/:id     | Delete user by ID (admin only) |

---

## 👑 RBAC Example

Use the `@Roles('admin')` decorator on any route:

```ts
@Roles('admin')
@Delete(':id')
remove(@Param('id') id: string) {
  return this.userService.remove(id);
}
```

Make sure the `user.role` value matches the required role.

---

## 🧠 To Do / Next Steps

- [ ] Replace in-memory store with PostgreSQL or DynamoDB
- [ ] Use Cognito Admin APIs for full user control
- [ ] JWT session management for Cognito users
- [ ] Unit & e2e testing

---


---

```

### ✅ Files to Generate & Save:
1. `README.md` – the full project documentation.
2. `.env.example` – sample environment variables.
3. `swagger.json` – optional Swagger spec file (auto-generated on runtime but can be saved if needed).

Let’s start with the files.

---

### 📄 `README.md`

I'll save the full `README.md` content just like we wrote above.

---

### 📄 `.env.example`

```env
# OAuth2 - Google
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# AWS Cognito
AWS_REGION=your_aws_region
AWS_USER_POOL_ID=your_user_pool_id
AWS_CLIENT_ID=your_cognito_client_id
```

---

### ⛲ How to Save It

Now, to add and commit these files:

```bash
# Save the README
echo "..." > README.md  # (paste the full content I gave earlier here)

# Save the example env
echo "GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
AWS_REGION=your_aws_region
AWS_USER_POOL_ID=your_user_pool_id
AWS_CLIENT_ID=your_cognito_client_id" > .env.example

# Stage & commit
git add README.md .env.example
git commit -m "docs: add README and example env config"
git push origin main  # or whichever branch you use
```

---
Well alrighty then, sugar! Let’s get the rest done proper.

---

### ✅ Generate Swagger Spec (`swagger.json`)

NestJS doesn't export `swagger.json` by default, but you can tweak your `main.ts` to generate one at runtime.

#### 🔧 Modify `main.ts`

```ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as fs from 'fs';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('NestJS Cognito Auth API')
    .setDescription('OAuth2 + Cognito + RBAC')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  // Save Swagger spec to swagger.json
  fs.writeFileSync('./swagger.json', JSON.stringify(document, null, 2));

  await app.listen(3000);
}
bootstrap();
```

#### 🏃 Run the app to generate `swagger.json`

```bash
npm run start:dev
```

Now you’ll have a shiny `swagger.json` in the root of your project!

---

### 📦 Create Zip File (Optional)

If you'd like a ZIP archive of your whole project (with all these goodies), you can run:

```bash
zip -r nestjs-cognito-auth-app.zip . -x "node_modules/*"
```

---

### ⬆️ Push to GitHub

If you're ready to commit & push everything:

```bash
git add README.md .env.example swagger.json
git commit -m "docs: add README, example .env, and Swagger spec"
git push origin main
```

---

### ✅ You now have:

- 📘 `README.md` with full project guide  
- 🧪 `.env.example` for your secrets  
- 📄 `swagger.json` with OpenAPI schema  
- 🚀 Your code ready to deploy or publish

---


## 🚀 Option 1: Deploy to AWS **EC2**

### 🧰 Requirements

- AWS account
- EC2 instance (Amazon Linux 2 or Ubuntu)
- SSH access
- Node.js + PM2 on EC2

---

### 🔧 Step-by-Step: EC2 Deployment

#### 1. **Provision an EC2 Instance**

- Go to EC2 dashboard → Launch Instance
- Choose Amazon Linux 2 or Ubuntu
- Add a security group: allow **ports 22 (SSH)** and **3000 (or 80/443)**
- Download your `.pem` key

#### 2. **SSH into EC2**

```bash
chmod 400 your-key.pem
ssh -i your-key.pem ec2-user@your-ec2-ip
```

#### 3. **Install Node.js, Git & PM2**

```bash
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs git
sudo npm install -g pm2
```

#### 4. **Clone Your Repo & Build**

```bash
git clone https://github.com/yourusername/nestjs-cognito-auth-app.git
cd nestjs-cognito-auth-app

npm install
npm run build
```

#### 5. **Run with PM2**

```bash
pm2 start dist/main.js --name nest-api
pm2 startup
pm2 save
```

#### 6. **(Optional) Reverse Proxy with Nginx**

Install Nginx and point it to `localhost:3000` to serve on port 80.

---

## 🛠 Option 2: Deploy to AWS **Lambda** (Serverless)

We'll use the [`@nestjs/cli`](https://docs.nestjs.com/cli/monorepo) with **AWS Serverless Application Model (SAM)** or **Serverless Framework**.

Let’s go the easy route first—with the **Serverless Framework**.

---

### 🔧 Step-by-Step: Lambda Deployment via Serverless Framework

#### 1. **Install Serverless CLI**

```bash
npm install -g serverless
```

#### 2. **Install Serverless Plugin for NestJS**

```bash
npm install --save @vendia/serverless-express aws-lambda
```

#### 3. **Add a `lambda.ts` file in `src`**

```ts
import { Handler } from 'aws-lambda';
import { createNestServer } from './main';
import serverlessExpress from '@vendia/serverless-express';

let cachedServer: Handler;

export const handler: Handler = async (event, context) => {
  if (!cachedServer) {
    const app = await createNestServer();
    cachedServer = serverlessExpress({ app });
  }

  return cachedServer(event, context);
};
```

Update your `main.ts` to export the server:

```ts
export async function createNestServer() {
  const app = await NestFactory.create(AppModule);
  await app.init();
  return app.getHttpAdapter().getInstance();
}
```

---

#### 4. **Configure `serverless.yml`**

```yaml
service: nestjs-auth-lambda

provider:
  name: aws
  runtime: nodejs18.x
  region: us-east-1
  memorySize: 512
  timeout: 10

functions:
  api:
    handler: dist/lambda.handler
    events:
      - http:
          path: /
          method: ANY
      - http:
          path: /{proxy+}
          method: ANY

package:
  individually: true

plugins:
  - serverless-offline
```

---

#### 5. **Deploy to Lambda**

```bash
npm run build
serverless deploy
```

---

 Let’s rewrite that bootstrap script for an **Ubuntu EC2 instance**, using the same setup:

✅ Node.js + PM2  
✅ Nginx reverse proxy on port 80  
✅ Git clone + NestJS install + build

---

## 📜 `ec2-bootstrap-ubuntu-nginx.sh`

Use this script on an **Ubuntu 22.04** or **20.04** EC2 instance:

```bash
#!/bin/bash

# --- Update System ---
apt update -y && apt upgrade -y

# --- Install Dependencies ---
apt install -y build-essential curl git nginx

# --- Install Node.js (v18) and npm ---
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# --- Install PM2 globally ---
npm install -g pm2

# --- Clone Your NestJS App ---
cd /home/ubuntu
git clone https://github.com/yourusername/nestjs-cognito-auth-app.git
cd nestjs-cognito-auth-app

# --- Optional: Set environment variables ---
cat <<EOF > .env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
AWS_REGION=your_aws_region
AWS_USER_POOL_ID=your_user_pool_id
AWS_CLIENT_ID=your_cognito_client_id
EOF

# --- Install dependencies & build the app ---
npm install
npm run build

# --- Run the app using PM2 ---
pm2 start dist/main.js --name nest-api
pm2 startup systemd
pm2 save

# --- Configure Nginx Reverse Proxy ---
cat <<EOL | sudo tee /etc/nginx/sites-available/nestjs
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

# --- Enable Nginx site and restart ---
ln -s /etc/nginx/sites-available/nestjs /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "✅ NestJS app is now live on port 80!"
```

---

## 🧑‍💻 How to Use It

### 1. **As EC2 User Data**

Paste into the **User data** section when launching a new **Ubuntu** EC2 instance.

> Don’t forget to open port 80 and 22 in your EC2 security group!

---

### 2. **Run Manually Over SSH**

```bash
scp -i your-key.pem ec2-bootstrap-ubuntu-nginx.sh ubuntu@your-ec2-ip:~
ssh -i your-key.pem ubuntu@your-ec2-ip

chmod +x ec2-bootstrap-ubuntu-nginx.sh
./ec2-bootstrap-ubuntu-nginx.sh
```

---

## 🌟 What’s Next?

Want to:
- Add **SSL (Let's Encrypt)** for HTTPS?
- Set up **GitHub Actions** for auto-deploy?
- Bake this into a custom **EC2 AMI**?

Well alright sugar, let’s get this script updated to work like a charm on **Ubuntu** using **NVM (Node Version Manager)** instead of installing Node.js globally. This is the more flexible and upgrade-friendly way to manage Node, bless your heart for thinking ahead!

---

## ✅ Updated Ubuntu EC2 Bootstrap Script Using NVM

```bash
#!/bin/bash

# --- Update & Install Essentials ---
apt update -y && apt upgrade -y
apt install -y build-essential git curl nginx

# --- Install NVM (Node Version Manager) ---
export NVM_DIR="/home/ubuntu/.nvm"
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

# --- Load NVM into current shell session ---
export NVM_DIR="/home/ubuntu/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# --- Install Node.js v18 with NVM ---
nvm install 18
nvm use 18
nvm alias default 18

# --- Install PM2 globally ---
npm install -g pm2

# --- Clone Your Repository ---
cd /home/ubuntu
git clone https://github.com/evillan0315/nestjs-cognito-auth-app.git
cd nestjs-cognito-auth-app

# --- Set Environment Variables ---
cat <<EOF > .env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
AWS_REGION=your_aws_region
AWS_USER_POOL_ID=your_user_pool_id
AWS_CLIENT_ID=your_cognito_client_id
EOF

# --- Install Dependencies & Build App ---
npm install
npm run build

# --- Start App with PM2 ---
pm2 start dist/main.js --name nest-api
pm2 startup systemd -u ubuntu --hp /home/ubuntu
pm2 save

# --- Configure Nginx Reverse Proxy ---
cat <<EOL > /etc/nginx/sites-available/nestjs
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

# --- Enable and restart Nginx ---
ln -s /etc/nginx/sites-available/nestjs /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "✅ NestJS App deployed and available on http://<your-ec2-ip>"
```

---

## 💡 Pro Tips

- This script assumes your EC2 instance is **Ubuntu 20.04+**
- Make sure you launch your instance with a Security Group that allows port **80 (HTTP)** and **22 (SSH)**
- Set real environment values in the `.env` section before launching

---


## ❤️ Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

---

## 🪪 License

[MIT](LICENSE)

---

## ✨ Author

**Eddie Villanueva**  
[GitHub](https://github.com/evillan0315) | [LinkedIn](https://www.linkedin.com/in/evillanueva0315)

