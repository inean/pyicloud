from ast import Is
from asyncio import Lock, Task, create_task, sleep

from ._state import IState


class Machine:
    """A Generic state machine, adapted from the Runner template"""

    def __init__(self):
        self._state: IState | None = None
        self._lock: Lock = Lock()
        self._task: Task | None = None
        self._loop: Task | None = None

    @property
    def state(self):
        """The current state the statemachine is in"""
        return self._state

    async def set_state(self, state):
        """Finalizes the previous state and then runs the new state"""
        if state is None:
            raise ValueError("state cannot be None")
        # Cancel the current task if it's running
        if self._state and self._task:
            self._skip()
        self._state = state
        await create_task(self._tick())

    async def _tick(self):
        """Runs the life cycle methods of the current state"""
        async with self._lock:
            assert self._state, "State must not be defined"
            self._state.enter()
            # keep a ref to execute coroutine of the current state
            self._task = create_task(self._state.execute())
            await self._task
            self._state.exit()
            self._task = None

    def _skip(self):
        """Interrupts the execution of the current state and finalizes it"""
        assert self._state
        if self._task and not self._task.done():
            self._task.cancel()

    async def run(self, state, until_complete=False):
        """
        Turns on the main loop of the StateMachine.
        This method does not resume previous state if called after stop()
        and the client needs to set the state manually.
        """
        # Update state to be run if it's not None
        if state:
            await self.set_state(state)
        if self._loop is not None:
            # already running
            return
        self._loop = create_task(self._play(until_complete))
        await self._loop

    def stop(self):
        """Turns off the main loop of the StateMachine"""
        if self._loop is None:
            return
        # interrupt currently executing state
        if self._state and self._task:
            self._skip()
        # stop the loop
        self._loop.cancel()
        self._state = None

    async def _play(self, until_complete=False):
        """ "It checks the status of the current state and its link to provide state sequencing"""
        while True:
            # current state is done playing
            if self._state and not self._task:
                next_state = self._state.validate_links()
                if isinstance(next_state, IState):
                    assert next_state
                    assert not self._lock.locked()
                    self._state.disable_links()
                    await self.set_state(next_state)
                    self._state.enable_links()
                # If no next state, and until_complete is True, then break
                if not next_state and until_complete:
                    break
            await sleep(0)

    @property
    def is_running(self):
        return self._loop is not None
