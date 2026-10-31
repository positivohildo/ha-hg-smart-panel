# HG Smart Home Panel Gateway - Home Assistant Add-on

Gateway oficial do painel de parede **HG Smart Home Panel** para o tablet antigo **ZH960 (Android 4.4.2 KitKat)**.

## O que este Add-on faz?

1. **Elimina qualquer intermediário:** Executa nativamente dentro do Home Assistant OS na porta `8090`.
2. **Otimização de Imagens (Pillow):** Redimensiona snapshots das câmeras para resoluções leves (480x320 / 640x360), garantindo fluidez e zero estouro de memória RAM (OOM) no Android 4.4.
3. **Temporizador Persistente da Airfryer:** Controla o desligamento programado da tomada inteligente da Airfryer (`switch.modulo_zigbee_1`) e emite anúncio de encerramento na Alexa da Sala (`media_player.alexa_sala`).
4. **Isolamento de Segurança:** Expõe apenas os 34 dispositivos mapeados no layout vertical da casa.

## Instalação

1. No Home Assistant, vá em **Configurações → Add-ons → Loja de Complementos**.
2. Clique no menu de **3 pontinhos** no canto superior direito e selecione **Repositórios**.
3. Adicione a URL:
   `https://github.com/positivohildo/ha-hg-smart-panel`
4. Na lista de add-ons, selecione **HG Smart Panel Gateway** e clique em **Instalar**.
5. Clique em **Iniciar** (e ative **Inicializar no arranque** e **Vigilante**).

## Configuração do Tablet

No aplicativo HG Smart Home Panel no tablet:
- **URL do Gateway / HA:** `http://172.30.0.2:8090/api/panel`
- **Chave de Acesso:** `hg-panel-7a41bc57d3b3fb49481f7a77a7e14202`
