# traefikjwtauthor
这个用来通过jwt鉴权
用户需要配置
TokenParam字段
和
WhiteList 字段
secret
#
## Configuration

### Static

```yaml
experimental:
  localPlugins:
    traefikjwtauthor:
      modulename: github.com/techidea8/traefikjwtauthor
```


```yaml
experimental:
  plugins:
    traefikjwtauthor:
      modulename: github.com/techidea8/traefikjwtauthor
      version: v0.0.1
```

### Dynamic configuration

```yaml
http:
  routers:
    my-router:
      middlewares:
        - traefik-real-ip
        - traefikjwtauthor
  middlewares:
    traefikjwtauthor:
      plugin:
        traefik-jwtauthor:
          whiteList:
            - "1.1.1.1/24"
          
```

#
## Configuration documentation

Supported configurations per body

| Setting           | Allowed values      | Required    | Description |
| :--               | :--                 | :--         | :--         |
| whiteList         | []string            | No          | 不需要鉴权的白名单 |
| param         | string            | No          | 鉴权参数对应的字段名 |
| secret         | string            | No          | 密钥 |

#