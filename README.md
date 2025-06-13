## Capture Module

Nanti sekalian sama parse traffic (jadiin .json) trus dilempar ke llm

1. Build and run:

```bash
docker-compose up --build
```

2. Custom target:

```bash
TARGET_URL={TARGET_URL} docker-compose up --build
```

3. Manual Docker run:

```bash
docker build -t zap-har-capture .
docker run -v $(pwd)/output:/workspace/output -e TARGET_URL=https://your-target.com zap-har-capture
```
