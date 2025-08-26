# Roadmap Completo DevOps 2025 - Guia de Estudos

## Índice
1. [Introdução ao DevOps](#1-introdução-ao-devops)
2. [Fundamentos - Sistemas Operacionais](#2-fundamentos---sistemas-operacionais)
3. [Redes e Protocolos](#3-redes-e-protocolos)
4. [Linguagens de Programação e Scripting](#4-linguagens-de-programação-e-scripting)
5. [Controle de Versão](#5-controle-de-versão)
6. [Containerização](#6-containerização)
7. [Orquestração de Containers](#7-orquestração-de-containers)
8. [CI/CD (Integração e Entrega Contínua)](#8-cicd-integração-e-entrega-contínua)
9. [Infraestrutura como Código (IaC)](#9-infraestrutura-como-código-iac)
10. [Cloud Computing](#10-cloud-computing)
11. [Monitoramento e Observabilidade](#11-monitoramento-e-observabilidade)
12. [Segurança DevSecOps](#12-segurança-devsecops)
13. [Ferramentas de Configuração](#13-ferramentas-de-configuração)
14. [GitOps](#14-gitops)
15. [Site Reliability Engineering (SRE)](#15-site-reliability-engineering-sre)
16. [Microservices e Arquitetura](#16-microservices-e-arquitetura)
17. [Projetos Práticos](#17-projetos-práticos)

---

## 1. Introdução ao DevOps

### 1.1 Conceitos Fundamentais

**O que é DevOps?**
DevOps é uma cultura, filosofia e conjunto de práticas que combina desenvolvimento de software (Dev) e operações de TI (Ops). O objetivo é encurtar o ciclo de vida do desenvolvimento de sistemas e fornecer entrega contínua com alta qualidade de software.

**Princípios Core do DevOps:**
- **Colaboração**: Quebrar silos entre desenvolvimento e operações
- **Automação**: Automatizar processos repetitivos e propensos a erros
- **Integração Contínua**: Integrar código frequentemente
- **Entrega Contínua**: Automatizar o processo de entrega
- **Monitoramento Contínuo**: Observar aplicações e infraestrutura em tempo real
- **Feedback Rápido**: Ciclos de feedback curtos para melhorias rápidas

**Benefícios do DevOps:**
- Velocidade de entrega aumentada
- Maior confiabilidade
- Melhor colaboração entre equipes
- Maior segurança
- Escalabilidade aprimorada

### 1.2 Cultura DevOps

**CALMS Framework:**
- **C**ulture: Mudança cultural organizacional
- **A**utomation: Automação de processos
- **L**ean: Princípios lean para eliminar desperdício
- **M**easurement: Métricas e monitoramento
- **S**haring: Compartilhamento de conhecimento

**Three Ways:**
1. **Flow**: Fluxo de trabalho da esquerda para direita
2. **Feedback**: Amplificar loops de feedback
3. **Continuous Learning**: Cultura de experimentação e aprendizado

---

## 2. Fundamentos - Sistemas Operacionais

### 2.1 Linux (Essencial)

**Distribuições Populares:**
- **Ubuntu**: Ideal para iniciantes
- **CentOS/RHEL**: Comum em empresas
- **Amazon Linux**: Para AWS
- **Alpine**: Leve para containers

**Comandos Essenciais:**
```bash
# Navegação e arquivos
ls, cd, pwd, mkdir, rmdir, rm, cp, mv, find, locate
chmod, chown, chgrp, umask

# Processos
ps, top, htop, kill, killall, nohup, jobs, fg, bg

# Rede
netstat, ss, ping, wget, curl, scp, rsync

# Sistema
df, du, free, uname, uptime, who, w, id

# Texto
cat, less, more, head, tail, grep, awk, sed, sort, uniq

# Compressão
tar, gzip, gunzip, zip, unzip
```

**Gerenciamento de Serviços:**
```bash
# SystemD
systemctl start|stop|restart|status service_name
systemctl enable|disable service_name
journalctl -u service_name

# Logs
tail -f /var/log/syslog
journalctl -f
```

### 2.2 Windows Server (Opcional)

**PowerShell Basics:**
- Cmdlets fundamentais
- Pipeline
- Scripts básicos
- Active Directory
- IIS

---

## 3. Redes e Protocolos

### 3.1 Fundamentos de Rede

**Modelo OSI e TCP/IP:**
- Camadas e suas funções
- Protocolos por camada
- Encapsulamento de dados

**Protocolos Essenciais:**
- **HTTP/HTTPS**: Comunicação web
- **TCP/UDP**: Transporte
- **DNS**: Resolução de nomes
- **DHCP**: Configuração automática de rede
- **SSH**: Acesso remoto seguro
- **FTP/SFTP**: Transferência de arquivos

### 3.2 Conceitos de Segurança de Rede

**Firewalls:**
- iptables (Linux)
- UFW (Ubuntu)
- Configuração básica de regras

**VPN e Túneis:**
- Conceitos básicos
- OpenVPN
- WireGuard

**Load Balancers:**
- Layer 4 vs Layer 7
- Algoritmos de balanceamento
- Health checks

---

## 4. Linguagens de Programação e Scripting

### 4.1 Bash/Shell Scripting

**Fundamentos:**
```bash
#!/bin/bash

# Variáveis
NAME="DevOps"
echo "Hello, $NAME"

# Condicionais
if [ "$NAME" = "DevOps" ]; then
    echo "Correct name"
fi

# Loops
for i in {1..5}; do
    echo "Number: $i"
done

# Funções
function deploy() {
    echo "Deploying application..."
}
```

**Scripts Úteis:**
- Backup automatizado
- Monitoramento de recursos
- Deploy de aplicações
- Log rotation

### 4.2 Python

**Por que Python em DevOps:**
- Automação de tarefas
- Scripts de deployment
- APIs e integrações
- Análise de logs
- Machine Learning Ops

**Bibliotecas Essenciais:**
```python
# Requests para APIs
import requests
response = requests.get('https://api.github.com')

# Subprocess para comandos do sistema
import subprocess
result = subprocess.run(['ls', '-la'], capture_output=True, text=True)

# Paramiko para SSH
import paramiko
ssh = paramiko.SSHClient()
ssh.connect('hostname', username='user', password='pass')

# Boto3 para AWS
import boto3
ec2 = boto3.client('ec2')
```

### 4.3 Go (Golang) - Crescente em DevOps

**Características:**
- Performance alta
- Compilação estática
- Concorrência nativa
- Usado em: Docker, Kubernetes, Terraform, Prometheus

**Exemplo Básico:**
```go
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "OK")
    })
    
    fmt.Println("Server starting on :8080")
    http.ListenAndServe(":8080", nil)
}
```

---

## 5. Controle de Versão

### 5.1 Git - Essencial

**Conceitos Fundamentais:**
- Repository, Working Directory, Staging Area
- Commits, Branches, Merges
- Remote repositories

**Comandos Essenciais:**
```bash
# Configuração inicial
git config --global user.name "Seu Nome"
git config --global user.email "seu@email.com"

# Básicos
git init
git clone <url>
git add <file>
git commit -m "message"
git push origin main
git pull origin main

# Branches
git branch feature-branch
git checkout feature-branch
git checkout -b feature-branch
git merge feature-branch

# Histórico
git log --oneline
git show <commit-hash>
git diff
```

**Git Flow:**
- Main/Master branch
- Develop branch
- Feature branches
- Release branches
- Hotfix branches

**GitHub/GitLab/Bitbucket:**
- Pull/Merge Requests
- Code Reviews
- Actions/CI integrado
- Issues e Project Management

### 5.2 Branching Strategies

**Git Flow vs GitHub Flow:**
- Git Flow: Mais estruturado para releases complexos
- GitHub Flow: Mais simples para continuous deployment

**Trunk-based Development:**
- Commits frequentes na main branch
- Feature flags para controle de features
- Releases mais rápidos

---

## 6. Containerização

### 6.1 Docker - Fundamental

**Conceitos Core:**
- Images vs Containers
- Dockerfile
- Docker Hub/Registry
- Volumes
- Networks

**Dockerfile Exemplo:**
```dockerfile
FROM node:16-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
```

**Comandos Essenciais:**
```bash
# Images
docker build -t app-name:tag .
docker images
docker rmi image-id
docker pull ubuntu:20.04

# Containers
docker run -d -p 8080:80 nginx
docker ps
docker stop container-id
docker rm container-id
docker exec -it container-id bash

# Volumes
docker volume create my-volume
docker run -v my-volume:/data ubuntu

# Networks
docker network create my-network
docker run --network my-network ubuntu
```

**Docker Compose:**
```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    depends_on:
      - db
      - redis

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine

volumes:
  postgres_data:
```

### 6.2 Melhores Práticas Docker

**Dockerfile Optimization:**
- Multi-stage builds
- Minimize layers
- Use specific tags
- Don't run as root
- Use .dockerignore

**Security:**
- Scan for vulnerabilities
- Use minimal base images
- Keep images updated
- Secrets management

---

## 7. Orquestração de Containers

### 7.1 Kubernetes - Essencial

**Arquitetura Kubernetes:**

**Master Components:**
- **API Server**: Interface para cluster
- **etcd**: Armazenamento de configuração
- **Scheduler**: Agenda pods nos nodes
- **Controller Manager**: Controla estado desejado

**Node Components:**
- **kubelet**: Agente que roda nos nodes
- **kube-proxy**: Networking
- **Container Runtime**: Docker, containerd

**Objetos Kubernetes:**

**Pod:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
  - name: nginx
    image: nginx:1.21
    ports:
    - containerPort: 80
```

**Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
        ports:
        - containerPort: 80
```

**Service:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  selector:
    app: nginx
  ports:
  - port: 80
    targetPort: 80
  type: LoadBalancer
```

**ConfigMap e Secret:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_url: "postgresql://localhost/mydb"
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
type: Opaque
data:
  password: cGFzc3dvcmQ=  # base64 encoded
```

**kubectl Commands:**
```bash
# Cluster info
kubectl cluster-info
kubectl get nodes

# Pods
kubectl get pods
kubectl describe pod pod-name
kubectl logs pod-name
kubectl exec -it pod-name -- bash

# Deployments
kubectl get deployments
kubectl scale deployment nginx-deployment --replicas=5
kubectl rollout status deployment/nginx-deployment

# Services
kubectl get services
kubectl port-forward service/nginx-service 8080:80

# Apply configurations
kubectl apply -f deployment.yaml
kubectl delete -f deployment.yaml
```

### 7.2 Helm - Package Manager para Kubernetes

**Conceitos:**
- Charts: Pacotes de templates Kubernetes
- Values: Configurações customizáveis
- Releases: Instâncias de charts

**Estrutura de Chart:**
```
mychart/
  Chart.yaml          # Metadados do chart
  values.yaml         # Valores padrão
  templates/          # Templates Kubernetes
    deployment.yaml
    service.yaml
    ingress.yaml
```

**Comandos Helm:**
```bash
# Instalar chart
helm install myapp ./mychart
helm install myapp bitnami/nginx

# Gerenciar releases
helm list
helm upgrade myapp ./mychart
helm rollback myapp 1
helm uninstall myapp

# Repositórios
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
helm search repo nginx
```

### 7.3 Alternativas ao Kubernetes

**Docker Swarm:**
- Mais simples que Kubernetes
- Integrado ao Docker
- Boa para clusters pequenos

**Nomad (HashiCorp):**
- Simpler orchestration
- Suporta containers e VMs
- Multi-region

---

## 8. CI/CD (Integração e Entrega Contínua)

### 8.1 Conceitos Fundamentais

**Continuous Integration (CI):**
- Integração frequente de código
- Builds automatizados
- Testes automatizados
- Feedback rápido

**Continuous Delivery (CD):**
- Automatização do processo de release
- Deploy para ambientes de staging
- Deploy para produção com aprovação manual

**Continuous Deployment:**
- Deploy automatizado para produção
- Zero downtime deployments
- Blue-green deployments
- Canary deployments

### 8.2 Jenkins - Tradicional mas Ainda Relevante

**Instalação e Configuração:**
```bash
# Via Docker
docker run -d -p 8080:8080 -p 50000:50000 jenkins/jenkins:lts
```

**Pipeline as Code (Jenkinsfile):**
```groovy
pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                echo 'Building...'
                sh 'npm install'
            }
        }
        
        stage('Test') {
            steps {
                echo 'Testing...'
                sh 'npm test'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                echo 'Deploying...'
                sh 'docker build -t myapp .'
                sh 'docker push registry/myapp'
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
    }
}
```

### 8.3 GitHub Actions - Moderno e Popular

**Workflow Example:**
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '16'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run tests
      run: npm test
    
    - name: Build application
      run: npm run build

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to production
      run: |
        echo "Deploying to production"
        # Add deployment steps here
```

### 8.4 GitLab CI/CD

**.gitlab-ci.yml Example:**
```yaml
stages:
  - build
  - test
  - deploy

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

build:
  stage: build
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE

test:
  stage: test
  script:
    - npm install
    - npm test

deploy:
  stage: deploy
  script:
    - kubectl set image deployment/myapp myapp=$DOCKER_IMAGE
  only:
    - main
```

### 8.5 Outras Ferramentas CI/CD Populares

**Azure DevOps:**
- Integração com Microsoft ecosystem
- Azure Pipelines para CI/CD
- Boards para project management

**CircleCI:**
- Cloud-native CI/CD
- Docker-first approach
- Parallelização automática

**ArgoCD (GitOps):**
- Continuous deployment para Kubernetes
- Declarative GitOps
- Web UI para visualização

**Tekton:**
- Cloud-native CI/CD para Kubernetes
- Pipeline as Code
- Reusable components

---

## 9. Infraestrutura como Código (IaC)

### 9.1 Terraform - Líder de Mercado

**Conceitos Fundamentais:**
- Providers: AWS, Azure, GCP, etc.
- Resources: Componentes de infraestrutura
- State: Estado atual da infraestrutura
- Modules: Componentes reutilizáveis

**Exemplo Básico:**
```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "main-vpc"
  }
}

# Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet"
  }
}

# EC2 Instance
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public.id

  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
  EOF

  tags = {
    Name = "web-server"
  }
}
```

**Comandos Terraform:**
```bash
# Inicializar
terraform init

# Planejar mudanças
terraform plan

# Aplicar mudanças
terraform apply

# Destruir infraestrutura
terraform destroy

# Validar configuração
terraform validate

# Formatar código
terraform fmt
```

**Terraform Modules:**
```hcl
# modules/ec2/main.tf
variable "instance_type" {
  description = "Type of EC2 instance"
  type        = string
  default     = "t2.micro"
}

variable "subnet_id" {
  description = "Subnet ID"
  type        = string
}

resource "aws_instance" "this" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = var.instance_type
  subnet_id     = var.subnet_id
}

output "instance_id" {
  value = aws_instance.this.id
}

# Usar o módulo
module "web_server" {
  source        = "./modules/ec2"
  instance_type = "t2.small"
  subnet_id     = aws_subnet.public.id
}
```

### 9.2 AWS CloudFormation

**Template Example (YAML):**
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Simple web server stack'

Parameters:
  InstanceType:
    Type: String
    Default: t2.micro
    AllowedValues:
      - t2.micro
      - t2.small
      - t2.medium

Resources:
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true

  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: true

  WebServer:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0c55b159cbfafe1d0
      InstanceType: !Ref InstanceType
      SubnetId: !Ref PublicSubnet
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          yum update -y
          yum install -y httpd
          systemctl start httpd
          systemctl enable httpd

Outputs:
  InstanceId:
    Description: 'ID of the EC2 instance'
    Value: !Ref WebServer
    Export:
      Name: !Sub '${AWS::StackName}-InstanceId'
```

### 9.3 Azure Resource Manager (ARM) Templates

### 9.4 Ansible - Configuration Management

**Conceitos:**
- Playbooks: Definições de configuração
- Inventory: Lista de hosts
- Modules: Unidades de trabalho
- Roles: Configurações reutilizáveis

**Inventory Example:**
```ini
[webservers]
web1.example.com
web2.example.com

[databases]
db1.example.com

[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

**Playbook Example:**
```yaml
---
- name: Setup web servers
  hosts: webservers
  become: yes
  
  tasks:
    - name: Install Apache
      apt:
        name: apache2
        state: present
        update_cache: yes
    
    - name: Start Apache service
      service:
        name: apache2
        state: started
        enabled: yes
    
    - name: Copy website files
      copy:
        src: ./website/
        dest: /var/www/html/
        owner: www-data
        group: www-data
        mode: '0644'
    
    - name: Open firewall for HTTP
      ufw:
        rule: allow
        port: '80'
        proto: tcp
```

**Ansible Roles Structure:**
```
roles/
  webserver/
    tasks/
      main.yml
    handlers/
      main.yml
    templates/
      apache.conf.j2
    files/
    vars/
      main.yml
    defaults/
      main.yml
    meta/
      main.yml
```

---

## 10. Cloud Computing

### 10.1 Amazon Web Services (AWS)

**Core Services:**

**Compute:**
- **EC2**: Virtual machines
- **Lambda**: Serverless functions
- **ECS/EKS**: Container services
- **Auto Scaling**: Automatic scaling

**Storage:**
- **S3**: Object storage
- **EBS**: Block storage
- **EFS**: File storage

**Database:**
- **RDS**: Relational databases
- **DynamoDB**: NoSQL database
- **ElastiCache**: In-memory caching

**Networking:**
- **VPC**: Virtual private cloud
- **Route 53**: DNS service
- **CloudFront**: CDN
- **ALB/NLB**: Load balancers

**AWS CLI Examples:**
```bash
# Configure AWS CLI
aws configure

# EC2
aws ec2 describe-instances
aws ec2 start-instances --instance-ids i-1234567890abcdef0

# S3
aws s3 ls
aws s3 cp file.txt s3://bucket-name/
aws s3 sync ./local-folder s3://bucket-name/folder/

# Lambda
aws lambda list-functions
aws lambda invoke --function-name my-function output.txt
```

**AWS CDK (Cloud Development Kit):**
```typescript
import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';

export class MyStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'MyVpc', {
      maxAzs: 2
    });

    const cluster = new ecs.Cluster(this, 'MyCluster', {
      vpc: vpc
    });
  }
}
```

### 10.2 Microsoft Azure

**Core Services:**
- **Virtual Machines**: Compute
- **App Service**: Web apps
- **AKS**: Azure Kubernetes Service
- **Storage Account**: Various storage types
- **SQL Database**: Managed SQL
- **Resource Groups**: Organization

**Azure CLI Examples:**
```bash
# Login
az login

# Resource Groups
az group create --name myResourceGroup --location eastus

# Virtual Machines
az vm create \
  --resource-group myResourceGroup \
  --name myVM \
  --image Ubuntu2204 \
  --admin-username azureuser \
  --generate-ssh-keys

# AKS
az aks create \
  --resource-group myResourceGroup \
  --name myAKSCluster \
  --node-count 1 \
  --enable-addons monitoring \
  --generate-ssh-keys
```

### 10.3 Google Cloud Platform (GCP)

**Core Services:**
- **Compute Engine**: Virtual machines
- **GKE**: Google Kubernetes Engine
- **Cloud Functions**: Serverless
- **Cloud Storage**: Object storage
- **Cloud SQL**: Managed databases

**gcloud CLI Examples:**
```bash
# Authentication
gcloud auth login

# Compute instances
gcloud compute instances create my-instance \
  --image-family ubuntu-2004-lts \
  --image-project ubuntu-os-cloud

# GKE
gcloud container clusters create my-cluster \
  --num-nodes=3 \
  --zone=us-central1-a
```

### 10.4 Multi-Cloud e Hybrid Cloud

**Estratégias:**
- Avoid vendor lock-in
- Disaster recovery
- Cost optimization
- Compliance requirements

**Ferramentas Multi-Cloud:**
- Terraform (supports all major clouds)
- Kubernetes (portable across clouds)
- Ansible (configuration management)

---

## 11. Monitoramento e Observabilidade

### 11.1 Conceitos Fundamentais

**Three Pillars of Observability:**
1. **Metrics**: Medições numéricas ao longo do tempo
2. **Logs**: Eventos discretos com timestamps
3. **Traces**: Jornada de requests através do sistema

**Tipos de Monitoramento:**
- **Infrastructure Monitoring**: CPU, memória, disk, network
- **Application Performance Monitoring (APM)**: Response times, errors
- **Business Metrics**: KPIs, conversions
- **Security Monitoring**: Intrusion detection, anomalias

### 11.2 Prometheus - Padrão para Metrics

**Arquitetura:**
- Pull-based model
- Time-series database
- PromQL query language
- Alertmanager para alertas

**prometheus.yml Configuration:**
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "first_rules.yml"
  - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'kubernetes-apiservers'
    kubernetes_sd_configs:
    - role: endpoints
    scheme: https
    tls_config:
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
```

**PromQL Examples:**
```promql
# CPU usage
100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Memory usage
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# HTTP request rate
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])

# 95th percentile response time
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

**Alerting Rules:**
```yaml
groups:
- name: example
  rules:
  - alert: HighCPUUsage
    expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage detected"
      description: "CPU usage is above 80% for more than 2 minutes"

  - alert: ServiceDown
    expr: up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Service {{ $labels.instance }} is down"
```

### 11.3 Grafana - Visualização

**Dashboard Configuration:**
```json
{
  "dashboard": {
    "title": "System Overview",
    "panels": [
      {
        "title": "CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
            "legendFormat": "CPU Usage %"
          }
        ]
      }
    ]
  }
}
```

**Data Sources:**
- Prometheus
- InfluxDB
- ElasticSearch
- CloudWatch
- Azure Monitor

### 11.4 ELK Stack (Elasticsearch, Logstash, Kibana)

**Logstash Configuration:**
```ruby
input {
  beats {
    port => 5044
  }
  file {
    path => "/var/log/nginx/access.log"
    start_position => "beginning"
  }
}

filter {
  if [fileset][module] == "nginx" {
    if [fileset][name] == "access" {
      grok {
        match => { "message" => "%{NGINXACCESS}" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
}
```

**Filebeat Configuration:**
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/nginx/*.log

output.logstash:
  hosts: ["logstash:5044"]

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
```

### 11.5 Modern Observability Stack

**Jaeger - Distributed Tracing:**
```yaml
# Docker Compose for Jaeger
version: '3.7'
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true
```

**OpenTelemetry:**
- Unified observability framework
- Vendor-neutral APIs
- Auto-instrumentation for popular languages

**Loki - Log Aggregation:**
```yaml
# Loki configuration
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /loki/boltdb-shipper-active
    cache_location: /loki/boltdb-shipper-cache
    shared_store: filesystem
  filesystem:
    directory: /loki/chunks

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
```

**Promtail (Loki Agent):**
```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
- job_name: system
  static_configs:
  - targets:
      - localhost
    labels:
      job: varlogs
      __path__: /var/log/*log
```

---

## 12. Segurança DevSecOps

### 12.1 Conceitos Fundamentais

**DevSecOps Philosophy:**
- Security as Code
- Shift Left Security
- Continuous Security
- Automated Security Testing

**Security Throughout SDLC:**
- **Plan**: Threat modeling, security requirements
- **Code**: Static analysis, secure coding practices
- **Build**: Dependency scanning, SAST
- **Test**: DAST, penetration testing
- **Deploy**: Infrastructure security, IAST
- **Monitor**: Security monitoring, incident response

### 12.2 Container Security

**Docker Security Best Practices:**
```dockerfile
# Use specific, minimal base images
FROM node:16-alpine

# Don't run as root
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Copy only necessary files
COPY package*.json ./
RUN npm ci --only=production

# Use non-root user
USER nextjs

# Use COPY instead of ADD
COPY --chown=nextjs:nodejs . .

# Expose specific ports only
EXPOSE 3000

# Use exec form for CMD
CMD ["npm", "start"]
```

**Image Scanning:**
```bash
# Trivy
trivy image nginx:latest

# Clair
docker run -d --name clair -p 6060:6060 quay.io/coreos/clair:latest

# Docker Scout
docker scout cves nginx:latest
```

### 12.3 Kubernetes Security

**Pod Security Standards:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
      requests:
        memory: "64Mi"
        cpu: "250m"
```

**Network Policies:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
spec:
  podSelector:
    matchLabels:
      role: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 8080
```

**RBAC (Role-Based Access Control):**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### 12.4 Secrets Management

**HashiCorp Vault:**
```bash
# Start Vault dev server
vault server -dev

# Set environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-only-token'

# Store secrets
vault kv put secret/myapp/config username=admin password=secret

# Retrieve secrets
vault kv get secret/myapp/config

# Use in applications
vault kv get -field=password secret/myapp/config
```

**Kubernetes Secrets:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=
  password: MWYyZDFlMmU2N2Rm
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        env:
        - name: USERNAME
          valueFrom:
            secretKeyRef:
              name: mysecret
              key: username
        - name: PASSWORD
          valueFrom:
            secretKeyRef:
              name: mysecret
              key: password
```

**AWS Secrets Manager:**
```python
import boto3
import json

def get_secret():
    secret_name = "prod/myapp/db"
    region_name = "us-west-2"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e

    secret = get_secret_value_response['SecretString']
    return json.loads(secret)
```

### 12.5 Security Scanning Tools

**Static Application Security Testing (SAST):**
- **SonarQube**: Code quality and security
- **Checkmarx**: Enterprise SAST
- **Bandit**: Python security linter

**Dynamic Application Security Testing (DAST):**
- **OWASP ZAP**: Open source web app scanner
- **Burp Suite**: Professional web security testing

**Dependency Scanning:**
- **Snyk**: Vulnerability scanning for dependencies
- **WhiteSource**: Open source security management
- **npm audit**: For Node.js projects

**Infrastructure as Code Security:**
- **Checkov**: Terraform/CloudFormation scanner
- **tfsec**: Terraform security scanner
- **Terrascan**: Multi-cloud IaC scanner

**CI/CD Integration Example:**
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Snyk to check for vulnerabilities
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
```

---

## 13. Ferramentas de Configuração

### 13.1 Ansible - Já Abordado em IaC

### 13.2 Chef

**Conceitos:**
- **Cookbooks**: Collections of recipes
- **Recipes**: Configuration definitions
- **Nodes**: Managed servers
- **Chef Server**: Central management

**Recipe Example:**
```ruby
# Install Apache
package 'apache2' do
  action :install
end

# Start and enable Apache service
service 'apache2' do
  action [:start, :enable]
end

# Create index.html
file '/var/www/html/index.html' do
  content '<h1>Hello from Chef!</h1>'
  mode '0644'
  owner 'www-data'
  group 'www-data'
end
```

**Cookbook Structure:**
```
mycookbook/
  metadata.rb
  README.md
  recipes/
    default.rb
  templates/
    default/
      apache.conf.erb
  files/
    default/
  attributes/
    default.rb
  libraries/
  definitions/
```

### 13.3 Puppet

**Concepts:**
- **Manifests**: Configuration files
- **Modules**: Reusable components
- **Classes**: Collections of resources
- **Facts**: System information

**Manifest Example:**
```puppet
# Install and configure Apache
class apache {
  package { 'apache2':
    ensure => installed,
  }

  service { 'apache2':
    ensure     => running,
    enable     => true,
    require    => Package['apache2'],
  }

  file { '/var/www/html/index.html':
    ensure  => file,
    content => '<h1>Hello from Puppet!</h1>',
    owner   => 'www-data',
    group   => 'www-data',
    mode    => '0644',
    require => Package['apache2'],
  }
}

include apache
```

### 13.4 SaltStack

**Architecture:**
- **Salt Master**: Central server
- **Salt Minions**: Managed nodes
- **States**: Configuration definitions
- **Pillars**: Secure data

**State Example:**
```yaml
# states/apache/init.sls
apache2:
  pkg.installed

apache2-service:
  service.running:
    - name: apache2
    - enable: True
    - require:
      - pkg: apache2

/var/www/html/index.html:
  file.managed:
    - source: salt://apache/files/index.html
    - user: www-data
    - group: www-data
    - mode: 644
    - require:
      - pkg: apache2
```

---

## 14. GitOps

### 14.1 Conceitos Fundamentais

**GitOps Principles:**
1. **Declarative**: System state described declaratively
2. **Versioned and Immutable**: Git as single source of truth
3. **Pulled Automatically**: Software agents pull changes
4. **Continuously Reconciled**: Ensure actual state matches desired state

**Benefits:**
- Improved security (no direct cluster access)
- Better auditability (all changes in Git)
- Easier rollbacks
- Consistent deployments

### 14.2 ArgoCD

**Installation:**
```bash
# Install ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Access UI
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Get admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

**Application Manifest:**
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/myorg/myapp-config
    targetRevision: HEAD
    path: k8s
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

**Repository Structure for GitOps:**
```
myapp-config/
  k8s/
    deployment.yaml
    service.yaml
    ingress.yaml
    kustomization.yaml
  overlays/
    dev/
      kustomization.yaml
      patch-deployment.yaml
    staging/
      kustomization.yaml
      patch-deployment.yaml
    prod/
      kustomization.yaml
      patch-deployment.yaml
```

### 14.3 Flux

**Installation:**
```bash
# Install Flux CLI
curl -s https://fluxcd.io/install.sh | sudo bash

# Bootstrap Flux
flux bootstrap github \
  --owner=myorg \
  --repository=fleet-infra \
  --branch=main \
  --path=./clusters/my-cluster \
  --personal
```

**GitRepository Source:**
```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: GitRepository
metadata:
  name: myapp
  namespace: flux-system
spec:
  interval: 1m
  ref:
    branch: main
  url: https://github.com/myorg/myapp-config
```

**Kustomization:**
```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1beta2
kind: Kustomization
metadata:
  name: myapp
  namespace: flux-system
spec:
  interval: 5m
  path: "./k8s"
  prune: true
  sourceRef:
    kind: GitRepository
    name: myapp
  targetNamespace: default
```

### 14.4 Kustomize

**Base Configuration:**
```yaml
# base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- deployment.yaml
- service.yaml

commonLabels:
  app: myapp
```

**Overlay for Production:**
```yaml
# overlays/prod/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
- ../../base

patchesStrategicMerge:
- patch-deployment.yaml

replicas:
- name: myapp
  count: 5
```

---

## 15. Site Reliability Engineering (SRE)

### 15.1 Conceitos Fundamentais

**SRE Principles:**
- **Service Level Objectives (SLOs)**: Target reliability levels
- **Service Level Indicators (SLIs)**: Metrics that matter
- **Service Level Agreements (SLAs)**: Contractual obligations
- **Error Budgets**: Allowed unreliability
- **Toil Reduction**: Minimize manual work

**SLI Examples:**
- Request latency
- Error rate
- System throughput
- Availability

**SLO Examples:**
- 99.9% availability (43.8 minutes downtime per month)
- 95% of requests complete in <200ms
- Error rate <0.1%

### 15.2 Error Budgets

**Calculation:**
```
Error Budget = 100% - SLO
Example: 99.9% SLO = 0.1% error budget

Monthly error budget (30 days):
30 days × 24 hours × 60 minutes × 0.1% = 43.2 minutes
```

**Policy Example:**
- If error budget > 0: Continue normal development velocity
- If error budget = 0: Freeze features, focus on reliability

### 15.3 Incident Management

**Incident Response Process:**
1. **Detection**: Automated monitoring alerts
2. **Response**: On-call engineer investigates
3. **Mitigation**: Immediate steps to reduce impact
4. **Resolution**: Fix root cause
5. **Post-mortem**: Learn and improve

**Post-mortem Template:**
```markdown
# Incident Post-mortem: [Title]

## Summary
Brief description of incident

## Impact
- Duration: X hours
- Users affected: N users
- Services affected: [list]

## Root Cause
Detailed explanation of what went wrong

## Timeline
- 14:00 - Incident began
- 14:05 - Alerts fired
- 14:10 - Incident response team engaged
- 14:30 - Mitigation deployed
- 15:00 - Full resolution

## Action Items
1. [ ] Fix root cause
2. [ ] Improve monitoring
3. [ ] Update runbooks
4. [ ] Conduct training

## Lessons Learned
What we learned and how to prevent similar incidents
```

### 15.4 Monitoring and Alerting Best Practices

**Alert Fatigue Prevention:**
- Alert on symptoms, not causes
- Use appropriate severity levels
- Implement alert suppression during maintenance
- Regular alert review and cleanup

**Alerting Runbooks:**
```markdown
# Alert: High CPU Usage

## Description
CPU usage is above 80% for more than 5 minutes

## Severity
Warning

## Investigation Steps
1. Check current CPU usage: `top` or `htop`
2. Identify high-CPU processes
3. Check system logs for errors
4. Verify if this is expected load

## Mitigation
1. If caused by runaway process: kill process
2. If legitimate high load: scale horizontally
3. If persistent: investigate application performance

## Escalation
If unable to resolve within 30 minutes, escalate to [team]
```

---

## 16. Microservices e Arquitetura

### 16.1 Conceitos de Microservices

**Características:**
- **Single Responsibility**: Each service does one thing well
- **Decentralized**: Independent development and deployment
- **Technology Agnostic**: Different tech stacks per service
- **Failure Isolation**: Failures don't cascade
- **Organized around Business Capabilities**

**Design Patterns:**

**API Gateway:**
```yaml
# Kong API Gateway Example
apiVersion: configuration.konghq.com/v1
kind: KongIngress
metadata:
  name: api-gateway
proxy:
  path: /api/v1
upstream:
  algorithm: round-robin
route:
  strip_path: true
```

**Service Discovery:**
```yaml
# Consul Service Discovery
apiVersion: v1
kind: Service
metadata:
  name: user-service
  annotations:
    consul.hashicorp.com/service-name: user-service
    consul.hashicorp.com/service-port: "8080"
spec:
  selector:
    app: user-service
  ports:
  - port: 8080
    targetPort: 8080
```

**Circuit Breaker Pattern:**
```python
# Python example with pybreaker
import pybreaker

# Create circuit breaker
db_breaker = pybreaker.CircuitBreaker(
    fail_max=5,
    reset_timeout=30,
    exclude=[KeyError]
)

@db_breaker
def call_external_service():
    # Make external call
    response = requests.get('https://api.example.com/data')
    return response.json()

# Usage
try:
    data = call_external_service()
except pybreaker.CircuitBreakerError:
    # Circuit is open, handle gracefully
    data = get_cached_data()
```

### 16.2 Service Mesh

**Istio - Popular Service Mesh:**

**Installation:**
```bash
# Install Istio
curl -L https://istio.io/downloadIstio | sh -
istioctl install --set values.defaultRevision=default

# Enable sidecar injection
kubectl label namespace default istio-injection=enabled
```

**Traffic Management:**
```yaml
# VirtualService for traffic routing
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews
spec:
  http:
  - match:
    - headers:
        end-user:
          exact: jason
    route:
    - destination:
        host: reviews
        subset: v2
  - route:
    - destination:
        host: reviews
        subset: v1
---
# DestinationRule for load balancing
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: reviews
spec:
  host: reviews
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
```

**Security Policies:**
```yaml
# PeerAuthentication for mTLS
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
---
# AuthorizationPolicy
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-read
  namespace: production
spec:
  selector:
    matchLabels:
      app: httpbin
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/sleep"]
    to:
    - operation:
        methods: ["GET"]
```

### 16.3 Event-Driven Architecture

**Message Brokers:**

**Apache Kafka:**
```yaml
# Kafka deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kafka
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kafka
  template:
    metadata:
      labels:
        app: kafka
    spec:
      containers:
      - name: kafka
        image: confluentinc/cp-kafka:latest
        env:
        - name: KAFKA_ZOOKEEPER_CONNECT
          value: zookeeper:2181
        - name: KAFKA_ADVERTISED_LISTENERS
          value: PLAINTEXT://kafka:9092
        - name: KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR
          value: "1"
```

**RabbitMQ:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rabbitmq
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rabbitmq
  template:
    metadata:
      labels:
        app: rabbitmq
    spec:
      containers:
      - name: rabbitmq
        image: rabbitmq:3-management
        env:
        - name: RABBITMQ_DEFAULT_USER
          value: admin
        - name: RABBITMQ_DEFAULT_PASS
          value: password
```

---

## 17. Projetos Práticos

### 17.1 Projeto 1: Pipeline CI/CD Completa

**Objetivo:** Criar pipeline completa para aplicação web

**Componentes:**
1. Aplicação Node.js simples
2. Dockerfile
3. GitHub Actions workflow
4. Deploy no Kubernetes
5. Monitoramento com Prometheus

**Estrutura do Projeto:**
```
my-web-app/
├── app/
│   ├── package.json
│   ├── server.js
│   └── public/
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── ingress.yaml
├── .github/
│   └── workflows/
│       └── ci-cd.yml
├── Dockerfile
└── docker-compose.yml
```

**Dockerfile:**
```dockerfile
FROM node:16-alpine

WORKDIR /app

COPY app/package*.json ./
RUN npm ci --only=production

COPY app/ .

RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001
USER nextjs

EXPOSE 3000

CMD ["node", "server.js"]
```

**GitHub Actions Workflow:**
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '16'
        cache: 'npm'
        cache-dependency-path: app/package-lock.json
    
    - name: Install dependencies
      run: cd app && npm ci
    
    - name: Run tests
      run: cd app && npm test
    
    - name: Run security audit
      run: cd app && npm audit

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker image
      run: docker build -t my-web-app:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'my-web-app:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to Kubernetes
      run: |
        # Update image tag in deployment
        sed -i "s/IMAGE_TAG/${{ github.sha }}/g" k8s/deployment.yaml
        kubectl apply -f k8s/
```

### 17.2 Projeto 2: Infraestrutura Multi-Ambiente com Terraform

**Objetivo:** Criar infraestrutura AWS para dev, staging, e prod

**Estrutura:**
```
terraform-infrastructure/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── terraform.tfvars
│   │   └── backend.tf
│   ├── staging/
│   └── prod/
├── modules/
│   ├── vpc/
│   ├── ec2/
│   ├── rds/
│   └── s3/
└── shared/
    ├── variables.tf
    └── outputs.tf
```

**VPC Module:**
```hcl
# modules/vpc/main.tf
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_subnet" "public" {
  count = length(var.public_subnets)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-public-${count.index + 1}"
    Environment = var.environment
    Type        = "public"
  }
}

resource "aws_subnet" "private" {
  count = length(var.private_subnets)

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.azs[count.index]

  tags = {
    Name        = "${var.environment}-private-${count.index + 1}"
    Environment = var.environment
    Type        = "private"
  }
}
```

### 17.3 Projeto 3: Observabilidade Stack Completa

**Objetivo:** Implementar observabilidade completa com Prometheus, Grafana, Loki, Jaeger

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  # Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'

  # Grafana
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning

  # Loki
  loki:
    image: grafana/loki:latest
    container_name: loki
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml
    volumes:
      - ./loki:/etc/loki

  # Promtail
  promtail:
    image: grafana/promtail:latest
    container_name: promtail
    volumes:
      - /var/log:/var/log:ro
      - ./promtail:/etc/promtail
    command: -config.file=/etc/promtail/config.yml

  # Jaeger
  jaeger:
    image: jaegertracing/all-in-one:latest
    container_name: jaeger
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  # Node Exporter
  node_exporter:
    image: prom/node-exporter:latest
    container_name: node_exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($|/)'

volumes:
  prometheus_data:
  grafana_data:
```

### 17.4 Projeto 4: GitOps com ArgoCD e Kustomize

**Objetivo:** Implementar GitOps completo com ambientes separados

**Estrutura do Repositório:**
```
gitops-demo/
├── apps/
│   └── my-app/
│       ├── base/
│       │   ├── kustomization.yaml
│       │   ├── deployment.yaml
│       │   ├── service.yaml
│       │   └── configmap.yaml
│       └── overlays/
│           ├── dev/
│           │   ├── kustomization.yaml
│           │   └── patch-replica.yaml
│           ├── staging/
│           │   ├── kustomization.yaml
│           │   └── patch-replica.yaml
│           └── prod/
│               ├── kustomization.yaml
│               └── patch-replica.yaml
├── argocd/
│   └── applications/
│       ├── my-app-dev.yaml
│       ├── my-app-staging.yaml
│       └── my-app-prod.yaml
└── infrastructure/
    └── namespaces/
        ├── dev.yaml
        ├── staging.yaml
        └── prod.yaml
```

**Base Kustomization:**
```yaml
# apps/my-app/base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- deployment.yaml
- service.yaml
- configmap.yaml

commonLabels:
  app: my-app
  version: v1.0.0

images:
- name: my-app
  newTag: latest
```

**Production Overlay:**
```yaml
# apps/my-app/overlays/prod/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: production

bases:
- ../../base

patchesStrategicMerge:
- patch-replica.yaml

images:
- name: my-app
  newTag: v1.2.0

configMapGenerator:
- name: app-config
  literals:
  - ENVIRONMENT=production
  - LOG_LEVEL=info
  behavior: merge
```

**ArgoCD Application:**
```yaml
# argocd/applications/my-app-prod.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app-prod
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: https://github.com/myorg/gitops-demo
    targetRevision: main
    path: apps/my-app/overlays/prod
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
    - CreateNamespace=true
    - PrunePropagationPolicy=foreground
    - PruneLast=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

### 17.5 Projeto 5: Microservices com Service Mesh

**Objetivo:** Implementar arquitetura de microservices com Istio

**Aplicações:**
- User Service (Node.js)
- Order Service (Python)
- Product Service (Go)
- API Gateway
- Frontend (React)

**Istio Configuration:**
```yaml
# Gateway para tráfego externo
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: microservices-gateway
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"

---
# VirtualService para roteamento
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: microservices
spec:
  hosts:
  - "*"
  gateways:
  - microservices-gateway
  http:
  - match:
    - uri:
        prefix: /api/users
    route:
    - destination:
        host: user-service
        port:
          number: 3000
  - match:
    - uri:
        prefix: /api/orders
    route:
    - destination:
        host: order-service
        port:
          number: 5000
  - match:
    - uri:
        prefix: /api/products
    route:
    - destination:
        host: product-service
        port:
          number: 8080
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: frontend
        port:
          number: 80

---
# DestinationRule com circuit breaker
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: user-service
spec:
  host: user-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 10
      http:
        http1MaxPendingRequests: 10
        maxRequestsPerConnection: 2
    circuitBreaker:
      consecutiveErrors: 3
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
```

---

## 18. Certificações DevOps Recomendadas

### 18.1 Certificações AWS
- **AWS Certified DevOps Engineer - Professional**
- **AWS Certified Solutions Architect - Associate**
- **AWS Certified Developer - Associate**

### 18.2 Certificações Kubernetes
- **Certified Kubernetes Administrator (CKA)**
- **Certified Kubernetes Application Developer (CKAD)**
- **Certified Kubernetes Security Specialist (CKS)**

### 18.3 Certificações Azure
- **Microsoft Azure DevOps Engineer Expert**
- **Microsoft Azure Solutions Architect Expert**

### 18.4 Certificações Google Cloud
- **Google Cloud Professional DevOps Engineer**
- **Google Cloud Professional Cloud Architect**

### 18.5 Outras Certificações Relevantes
- **Docker Certified Associate**
- **HashiCorp Terraform Associate**
- **Red Hat Certified System Administrator**

---

## 19. Roadmap de Estudos Recomendado

### 19.1 Nível Iniciante (2-3 meses)
**Semana 1-2: Fundamentos**
- Linux básico e comandos essenciais
- Git e controle de versão
- Conceitos de rede básicos

**Semana 3-4: Containerização**
- Docker fundamentals
- Dockerfile e melhores práticas
- Docker Compose

**Semana 5-6: Cloud Basics**
- Escolher um cloud provider (AWS recomendado)
- Conceitos básicos de cloud
- EC2, S3, VPC básicos

**Semana 7-8: CI/CD Básico**
- GitHub Actions ou GitLab CI
- Pipeline simples
- Deploy automatizado

**Semana 9-12: Projeto Prático**
- Aplicação web simples
- Pipeline CI/CD completa
- Deploy no cloud

### 19.2 Nível Intermediário (3-4 meses)
**Mês 1: Kubernetes**
- Conceitos fundamentais
- Deployments, Services, ConfigMaps
- kubectl comandos essenciais

**Mês 2: Infraestrutura como Código**
- Terraform basics
- AWS/Azure resource management
- Modules e best practices

**Mês 3: Monitoramento**
- Prometheus e Grafana
- Alerting básico
- Log aggregation com ELK

**Mês 4: Projeto Intermediário**
- Aplicação multi-tier
- Kubernetes deployment
- Monitoring completo

### 19.3 Nível Avançado (4-6 meses)
**Mês 1-2: Orquestração Avançada**
- Helm charts
- Kubernetes operators
- Service mesh (Istio)

**Mês 3: GitOps e Advanced CI/CD**
- ArgoCD ou Flux
- Blue-green deployments
- Canary releases

**Mês 4: Segurança DevSecOps**
- Container security
- Secrets management
- Security scanning integration

**Mês 5: Observabilidade Avançada**
- Distributed tracing
- SRE practices
- Incident response

**Mês 6: Projeto Master**
- Microservices architecture
- Complete observability stack
- Production-ready GitOps

---

## 20. Ferramentas por Categoria - Resumo Executivo

### 20.1 Controle de Versão
- **Git** (essencial)
- GitHub/GitLab/Bitbucket
- Git Flow/GitHub Flow

### 20.2 Containerização
- **Docker** (fundamental)
- Podman (alternativa)
- BuildKit (advanced builds)

### 20.3 Orquestração
- **Kubernetes** (padrão da indústria)
- **Helm** (package manager)
- Docker Swarm (simpler alternative)

### 20.4 CI/CD
- **GitHub Actions** (popular)
- **GitLab CI** (integrated)
- Jenkins (traditional)
- ArgoCD (GitOps)
- CircleCI, Azure DevOps

### 20.5 Infrastructure as Code
- **Terraform** (multi-cloud leader)
- AWS CloudFormation
- Azure ARM Templates
- Pulumi (programming languages)

### 20.6 Configuration Management
- **Ansible** (agentless)
- Chef (Ruby-based)
- Puppet (declarative)
- SaltStack (Python-based)

### 20.7 Cloud Platforms
- **AWS** (market leader)
- **Microsoft Azure**
- **Google Cloud Platform**
- DigitalOcean, Linode (simpler)

### 20.8 Monitoring & Observability
- **Prometheus** (metrics)
- **Grafana** (visualization)
- ELK Stack (logging)
- Jaeger (tracing)
- DataDog, New Relic (commercial)

### 20.9 Security
- **HashiCorp Vault** (secrets)
- Snyk (vulnerability scanning)
- OWASP ZAP (security testing)
- Falco (runtime security)

### 20.10 Service Mesh
- **Istio** (feature-rich)
- Linkerd (lightweight)
- Consul Connect

---

## 21. Recursos de Estudo Complementares

### 21.1 Documentação Oficial
- Kubernetes.io
- Docker.com/docs
- Terraform.io/docs
- Prometheus.io/docs

### 21.2 Plataformas de Aprendizado
- **A Cloud Guru**
- **Pluralsight**
- **Linux Academy**
- **KodeKloud** (hands-on labs)
- **Udemy** (cursos específicos)

### 21.3 Livros Recomendados
- "The Phoenix Project" - Gene Kim
- "The DevOps Handbook" - Gene Kim
- "Site Reliability Engineering" - Google
- "Kubernetes: Up and Running" - Kelsey Hightower
- "Infrastructure as Code" - Kief Morris

### 21.4 Blogs e Sites
- DevOps.com
- The New Stack
- InfoQ DevOps
- AWS Blog
- CNCF Blog

### 21.5 Podcasts
- DevOps Chat
- The Cloudcast
- Software Engineering Daily
- DevOps and Docker Talk

### 21.6 Comunidades
- Reddit: r/devops, r/kubernetes
- Discord: DevOps communities
- Stack Overflow
- GitHub Discussions
- LinkedIn DevOps Groups

---

## 22. Dicas Finais para Sucesso

### 22.1 Hands-on Learning
- **Pratique constantemente**: DevOps é uma disciplina prática
- **Build projects**: Crie projetos reais, não apenas tutoriais
- **Break things**: Aprenda com falhas e troubleshooting
- **Document everything**: Mantenha documentação dos seus labs

### 22.2 Community Engagement
- **Participe de comunidades**: Reddit, Discord, Slack
- **Contribua para projetos open source**: GitHub contributions
- **Attend meetups**: Local DevOps meetups e conferências
- **Share knowledge**: Blog posts, apresentações

### 22.3 Continuous Learning
- **Stay updated**: DevOps evolui rapidamente
- **Follow thought leaders**: No Twitter, LinkedIn
- **Read release notes**: Novas features das ferramentas
- **Experiment with new tools**: Sempre teste novas soluções

### 22.4 Career Development
- **Build a portfolio**: GitHub com projetos demonstráveis
- **Get certified**: Certificações validam conhecimento
- **Network**: Conecte-se com outros profissionais
- **Mentor others**: Ensinar solidifica seu aprendizado

### 22.5 Soft Skills Importantes
- **Communication**: DevOps é sobre colaboração
- **Problem-solving**: Debugging e troubleshooting
- **Automation mindset**: Sempre pense em automatizar
- **Security awareness**: Segurança em primeiro lugar

---

## Conclusão

Este roadmap apresenta um caminho estruturado para dominar DevOps em 2025. O segredo é a prática consistente e a aplicação dos conceitos em projetos reais. DevOps não é apenas sobre ferramentas, mas sobre cultura, processos e mentalidade de melhoria contínua.

Lembre-se:
- **Comece pequeno**: Não tente aprender tudo de uma vez
- **Seja prático**: Implemente o que aprender
- **Seja paciente**: DevOps é uma jornada, não um destino
- **Mantenha-se atualizado**: A tecnologia evolui constantemente

Boa sorte na sua jornada DevOps! 🚀

---

*Este guia foi criado para ser um recurso completo de estudos. Atualize-o regularmente conforme novas tecnologias e práticas surgirem no mercado.*