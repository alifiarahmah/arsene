# Stop existing containers

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

```sh
curl http://localhost:11434/api/generate -d '{
  "model": "phi3:mini",
  "prompt": "Hello world",
  "stream": false
}'
```

chmod +x ./reasoning-module/entrypoint.sh
