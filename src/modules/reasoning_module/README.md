# Stop existing containers

# TODO: add separate repository for docker-compose(?)

```sh
docker compose down
```

# Start fresh

```sh
docker compose up -d
```

# Check logs

```sh
docker logs reasoning-module -f
```

# Test API

token webui alip: cd4744b1831ee7a580c7e5fe38a2e2a9d9c777d65608bb36745d6f6fd9910dfe

```sh
curl http://localhost:11434/api/generate -d '{
  "model": "phi3:mini",
  "prompt": "Hello world",
  "stream": false
}'
```

```sh
curl http://61.71.33.195:54012/v1/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer cd4744b1831ee7a580c7e5fe38a2e2a9d9c777d65608bb36745d6f6fd9910dfe" \
    -d '{
      "model": "mixtral:8x7b",
      "prompt": "San Francisco is a",
      "max_tokens": 128,
      "temperature": 0.6
    }'
```

chmod +x ./reasoning-module/entrypoint.sh
