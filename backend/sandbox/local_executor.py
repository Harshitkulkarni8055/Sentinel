from sandbox.executor import SandboxExecutor


class LocalSandboxExecutor(SandboxExecutor):
    def execute(self, action):
        return {
            "status": "ready",
            "action": action,
        }