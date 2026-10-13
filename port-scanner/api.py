import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from scanner import scan_port, validate_ports, validate_target


app = FastAPI(
    title="Cyber Lab Port Scanner API",
    description=(
        "A learning API for authorized TCP port scanning of "
        "localhost and private IP addresses."
    ),
    version="1.0.0",
)


class ScanRequest(BaseModel):
    target: str = Field(
        min_length=1,
        max_length=253,
        description="Local hostname or private IP address",
        examples=["127.0.0.1"],
    )

    start_port: int = Field(
        default=1,
        ge=1,
        le=65535,
        description="First TCP port to scan",
    )

    end_port: int = Field(
        default=1024,
        ge=1,
        le=65535,
        description="Last TCP port to scan",
    )

    timeout: float = Field(
        default=0.5,
        ge=0.1,
        le=5.0,
        description="Connection timeout in seconds",
    )

    workers: int = Field(
        default=100,
        ge=1,
        le=200,
        description="Number of concurrent scanner threads",
    )


class OpenPort(BaseModel):
    port: int
    service: str
    status: str


class ScanResponse(BaseModel):
    target: str
    resolved_ip: str
    start_port: int
    end_port: int
    ports_checked: int
    scan_time: str
    duration_seconds: float
    open_port_count: int
    open_ports: list[OpenPort]


def perform_scan(request: ScanRequest) -> dict:
    validate_ports(request.start_port, request.end_port)
    target_ip = validate_target(request.target)

    started = time.perf_counter()
    open_ports = []

    with ThreadPoolExecutor(max_workers=request.workers) as executor:
        jobs = [
            executor.submit(
                scan_port,
                target_ip,
                port,
                request.timeout,
            )
            for port in range(
                request.start_port,
                request.end_port + 1,
            )
        ]

        for job in as_completed(jobs):
            result = job.result()

            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda item: item["port"])
    duration = round(time.perf_counter() - started, 3)

    return {
        "target": request.target,
        "resolved_ip": target_ip,
        "start_port": request.start_port,
        "end_port": request.end_port,
        "ports_checked": request.end_port - request.start_port + 1,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": duration,
        "open_port_count": len(open_ports),
        "open_ports": open_ports,
    }


@app.get("/")
def home() -> dict:
    return {
        "name": "Cyber Lab Port Scanner API",
        "version": "1.0.0",
        "status": "running",
        "documentation": "/docs",
    }


@app.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
    }


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> dict:
    try:
        return await asyncio.to_thread(
            perform_scan,
            request,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        print(f"Unexpected scan error: {error}")

        raise HTTPException(
            status_code=500,
            detail="The scan could not be completed.",
        ) from error
