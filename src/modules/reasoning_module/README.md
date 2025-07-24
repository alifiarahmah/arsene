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

## localhost
```sh
curl http://localhost:11434/api/generate -H "Content-Type: application/json" -H "Authorization: Bearer be77fef88ddb58dbe9b3f94e5a9b300101da1b8a51ece515c17cd2de058bab9e" -d '{
      "model": "mistral:7b-instruct-v0.2-q8_0",
      "prompt": "hello, who are you?",
      "stream": false,
      "max_tokens": 128,
      "temperature": 0.1
    }'
```

chmod +x ./reasoning-module/entrypoint.sh
