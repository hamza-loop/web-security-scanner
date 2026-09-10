import asyncio
import aiohttp
import logging

logger = logging.getLogger(__name__)

async def check_url(session, url, semaphore):

    """
    Check a URL asynchronously while respecting
    the maximum concurrency limit.
    """
    async with semaphore:
        logger.info("Checking URL: %s", url)

        try:
            async with session.get(url, timeout = 10 ) as response:
                status = response.status
                logger.info("URL: %s, Status: %s", url, status)
                return {"url": url, "status": status}
        
        except asyncio.TimeoutError:
            logger.error("Async request timed out for URL: %s", url)
            return{"url": url, "status": None, "error": "Async request timed out"}
        
        except aiohttp.ClientError as e:
            logger.error("Error checking URL %s: %s",url,e)
            return {"url": url, "status": None, "error": str(e)}
        
async def scan_urls(urls, max_concurrent_requests=5):
    """
    Scan multiple URLs concurrently.
    """
    semaphore = asyncio.Semaphore(max_concurrent_requests)

    async with aiohttp.ClientSession() as session:
        tasks = [check_url(session, url, semaphore) for url in urls]
        results = await asyncio.gather(*tasks)

    return results

def run_async_scan(urls, max_concurrent_requests=5):
    """
    Synchronous entry point for the async scanner.
    """

    return asyncio.run(
        scan_urls(urls, max_concurrent_requests)
    )