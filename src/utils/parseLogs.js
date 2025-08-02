  export function parseLogData(logText) {
    const lines = logText.split('\n').filter(Boolean)

    return lines.map(line => {
      const match = line.match(/\[(.*?)\] SRC:(.*?) DST:(.*?) PORT:(\d+) PROTO:(\w+)/)
      if (!match) return null

      const [, timestamp, src, dst, port, proto] = match

      const isPublicIP = !/^10\.|^192\.168\.|^172\.16\./.test(dst)
      const uncommonPort = !["80", "443", "22", "53"].includes(port)
      const unknownProto = !["TCP", "UDP", "ICMP"].includes(proto.toUpperCase())

      const suspicious = isPublicIP || uncommonPort || unknownProto

      return {
        timestamp,
        src,
        dst,
        port,
        proto,
        suspicious
      }
    }).filter(Boolean)
  }
