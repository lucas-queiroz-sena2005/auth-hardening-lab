# Security Authentication Project

Este projeto implementa um backend de autenticação utilizando a standard library do Go e um banco de dados SQLite embutido, configurado com Write-Ahead Logging (WAL). 

A aplicação funciona de forma *standalone* (sem dependências externas) com "Zero-Config Headless Execution", gerando seu próprio banco de dados local e os certificados TLS automaticamente caso não existam.

## Arquitetura

- **Database:** SQLite embutido.
- **Autenticação:** Stateful session authentication usando cookies opacos com as flags `HttpOnly`, `Secure` e `SameSite=Strict`.
- **Mecanismos de Segurança:** 
  - *Rate Limiting* sensível a IPv6 e IPv4.
  - Normalização determinística de Unicode (NFC) contra *homograph attacks*.
  - *Constant-Time Verification* e *Dummy Hashing* contra *Timing Attacks*.
  - Geração autônoma de certificados TLS (curvas X25519 e P256).
  - System Registration Key opcional para restringir a criação de contas.

---

## Alinhamento com a OWASP Top 10 (2021)

O design aborda proativamente múltiplas categorias da OWASP Top 10:

1. **A01 - Broken Access Control:**
   Sessões mantidas no backend com session tokens de 32 bytes gerados via RNG e validados por HMAC. Utiliza cookies `HttpOnly`, `Secure` e `SameSite=StrictMode`, prevenindo roubo de sessão e requisições CSRF.

2. **A02 - Cryptographic Failures:**
   Credenciais não são armazenadas em plain text. O sistema força HTTPS gerando certificados TLS 1.2+ na inicialização. 
   - **Salting Automático:** As senhas usam *bcrypt* (cost 12). O algoritmo gera um *salt* aleatório exclusivo para cada usuário de forma transparente, invalidando ataques com *Rainbow Tables*.
   - **Chave HMAC:** Diferente do *salt* (que protege hashes no banco), a integridade das sessões é protegida por uma assinatura HMAC usando uma Chave Criptográfica secreta, garantindo que os *session tokens* não possam ser forjados por atacantes.

3. **A03 - Injection:**
   O acesso ao banco de dados é feito estritamente através de *Prepared Statements* (via driver SQL do Go), eliminando vulnerabilidades de SQL Injection.

4. **A04 - Insecure Design:**
   Para prevenir *User Enumeration*, a API executa um *Dummy Hash* bcrypt quando o usuário consultado não existe. Isso garante que o tempo de resposta seja consistente (constant-time) independente da falha ter ocorrido no usuário ou na senha.

5. **A05 - Security Misconfiguration:**
   Como a execução é *Zero-Config*, o uso de HTTPS e headers seguros é habilitado por padrão. Conexões com versões obsoletas do TLS são rejeitadas.

6. **A07 - Identification and Authentication Failures:**
   Implementação de *Token Bucket Rate Limiting* que agrupa requisições IPv6 pelo prefixo `/64`. Isso mitiga efetivamente táticas modernas de *Credential Stuffing* e *Brute Force* baseadas em rotação de IPs. 

7. **A08 - Software and Data Integrity Failures:**
   O projeto foca em utilizar a *Standard Library* do ecossistema Go. Sem dependências pesadas de frameworks externos, a superfície exposta para *Supply Chain Attacks* é minimizada.

*(Nota: As categorias A06 (Vulnerable Components), A09 (Security Logging Failures) e A10 (SSRF) da OWASP Top 10 não foram listadas porque não se aplicam ao escopo atual do projeto. O sistema não utiliza componentes de terceiros vulneráveis por design, foca puramente em mitigação ativa, e não realiza requisições para URLs externas).*

---

## Como Executar

Este projeto foi construído para ser totalmente *standalone*. O frontend (`index.html`) já está embutido dentro do código. Isso significa que você só precisa enviar e rodar um único arquivo.

### Usando os Executáveis Prontos
Basta rodar o arquivo correspondente ao seu sistema operacional:
- No Linux: abra o terminal e execute `./auth-linux`
- No Windows: dê dois cliques no `auth-windows.exe`

Ao iniciar, o executável criará automaticamente uma pasta `data/` com o banco de dados e os certificados TLS. O servidor avisará que subiu com sucesso. Basta acessar `https://localhost:8443` no seu navegador.

### Compilando a partir do Código-Fonte (Para Desenvolvedores)
Se preferir rodar ou modificar o código-fonte localizado em `src/`, você tem duas opções:

### Opção 1: Nix Shell (Recomendado)
```bash
nix-shell shell.nix
cd src
go run main.go
```
Acesse: `https://localhost:8443`

### Opção 2: Docker Compose
```bash
cd src
docker compose up --build -d
```
Parar o container: `docker compose down`

---

## API & Endpoints

### 1. Registrar Usuário (`/reg`)
```bash
curl -k -X POST https://localhost:8443/reg \
  -H "Content-Type: application/json" \
  -d '{"u":"alice", "p":"securepass123", "k":"admin-key"}'
```
*(Nota: O parâmetro `"k"` - System Registration Key - só é necessário se a chave estiver habilitada no backend).*

### 2. Login (`/log`)
```bash
curl -k -X POST https://localhost:8443/log \
  -H "Content-Type: application/json" \
  -d '{"u":"alice", "p":"securepass123"}'
```

### 3. Teste de Rate Limiting (Burst 5, 1 req/sec)
Execute requisições em loop para testar o limite:
```bash
for i in {1..10}; do
  curl -k -s -o /dev/null -w "%{http_code}\n" -X POST https://localhost:8443/log \
    -H "Content-Type: application/json" \
    -d '{"u":"alice", "p":"wrongpassword"}';
done
```
Após 5 requisições rápidas, os códigos de retorno mudarão para `429` (Too Many Requests).
