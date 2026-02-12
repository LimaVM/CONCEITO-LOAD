# ConceitoLoad - Load Balancer TCP para RDP

Load Balancer TCP de alta performance com Sticky Sessions para RDP.

## Características

- **Sticky Sessions**: Hash djb2 por username (mstshash)
- **Health Check**: Verifica backends a cada 20s
- **Anti-Spam**: Rate limiting + blacklist automática
- **Dashboard Web**: Gerenciamento em tempo real (porta 3000)
- **Multi-Core**: Utiliza todos os CPUs via cluster
- **Persistência**: Configurações salvas em JSON

## Instalação Ubuntu 24.04 (Produção)

```bash
# 1. Transfira os arquivos para o servidor
scp -r ./* usuario@servidor:/tmp/conceitoload/

# 2. No servidor, execute:
cd /tmp/conceitoload
sudo bash install.sh
```

O script automaticamente:
- Instala Node.js 22 LTS
- Cria usuário de sistema `conceitoload`
- Configura limites de file descriptors (65535)
- Otimiza parâmetros TCP do kernel
- Instala e inicia serviço systemd

### Comandos Úteis

```bash
sudo systemctl status conceitoload    # Ver status
sudo journalctl -u conceitoload -f    # Ver logs
sudo systemctl restart conceitoload   # Reiniciar
sudo systemctl stop conceitoload      # Parar
```

## Instalação Manual

```bash
npm install
npm start
```

## Configuração (.env)

```env
PORTS=3389,49155
TARGETS=10.0.0.90:3389,10.0.0.213:3389,10.0.0.80:49155
```

## Dashboard

Acesse `http://servidor:3000` para:
- Ver sessões ativas
- Gerenciar rotas manuais
- Banir IPs/usuários
- Ajustar pesos dos servidores
- Ativar modo aprendizado

## Arquivos

| Arquivo | Descrição |
|---------|-----------|
| `index.js` | Código principal |
| `.env` | Configuração de portas/servidores |
| `concload-data.json` | Dados persistidos |
| `install.sh` | Instalador Ubuntu |
| `conceitoload.service` | Serviço systemd |

## Licença

ISC - Conceito Tecnologia
