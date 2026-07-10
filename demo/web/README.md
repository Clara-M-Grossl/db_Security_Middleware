# Serviço Web de Teste

Uma aplicação Node.js / Express construída estritamente para demonstrar a eficácia do **Database Security Middleware** de forma prática e visual.

A aplicação simula dois contextos de microsserviços no mesmo servidor Node:

1. **Clínica**
2. **E-commerce**

Nenhum dado é criptografado no código Node.js. Toda a segurança é delegada à camada de rede, mas a aplicação interage com o banco de forma totalmente transparente como se estivesse lidando com dados normais.

## Como rodar o ambiente Teste completo

A maneira mais fácil de testar essa aplicação é rodá-la em conjunto com o Middleware usando o Docker Compose na pasta raiz do projeto.

1. Volte para a raiz do repositório (`../../`)
2. Execute o comando:

```bash
docker-compose up -d --build
```

Isso irá construir o Middleware , levantar as instâncias do PostgreSQL, inicializar o Vault e, por fim, rodar esta aplicação Node.js na porta `3000`.

### Acessando a Aplicação

Abra o navegador e acesse:
[http://localhost:3000](http://localhost:3000)

Lá você encontrará a interface para inserir pacientes e fazer buscas e poderá validar como os dados estão aparecendo corretamente no frontend, mesmo estando fisicamente encriptados no disco do banco de dados.

## Rodando o serviço Web isoladamente

Se você já tem os Middlewares e os bancos rodando remotamente e quiser rodar apenas o Node.js na sua máquina:

1. Instale as dependências:

```bash
npm install
```

2. Inicialize o servidor definindo as variáveis apontando para os IPs do Gateway

```bash
PORT=3000 \
DB_HOST=127.0.0.1 \
DB_PORT=8000 \
DB_ECOMMERCE_HOST=127.0.0.1 \
DB_ECOMMERCE_PORT=8001 \
npm start
```
