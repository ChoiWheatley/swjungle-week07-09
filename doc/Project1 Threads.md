# Project1 Threads

스레드가 생성될 때마다 스케줄에 컨텍스트가 하나씩 추가된다. `thread_create` 함수를 호출하며 넣은 함수 포인터는 스레드 단위의 main 함수가 되어 해당 함수를 벗어나면 스레드가 종료된다.

스케줄러는 스레드가 정확히 하나씩 실행할 수 있도록 스케줄링을 한다. 아무 스레드도 돌지 않는다면, 특수 스레드인 `idle` 스레드를 만들어 돌린다.

스레드, 컨텍스트는 1대1로 존재하며, 스케줄러가 강제적으로 한 스레드에서 다른 스레드로 문맥전환(context-switch) 하기 위해 기존 스레드의 컨텍스트를 저장하고 다음 스레드를 복원하는 작업을 수행하여야 한다. 이 작업을 [thread_launch](../threads/thread.c#thread_launch) 함수에서 수행한다.

GDB를 사용하면서 컨텍스트 스위칭이 일어나는 타이밍을 확인할 수도 있다. 대표적으로 [`do_iret()`](../threads/thread.c#do_iret) 함수에서 `iret`을 실행할 때 어떻게 되는지 확인해보자.

기본적으로, PintOS는 새 스레드를 만들때 고정 크기의 실행스택이 할당된다. 따라서 유저 프로그램이 너무 큰 지역변수를 스레드 안에서 선언해버리면 커널패닉이 발생할 수도 있다. 대안으로 블록/페이지 할당자가 있다고. ([Memory Allocation](https://casys-kaist.github.io/pintos-kaist/appendix/memory_allocation.html))

## Source Files

- [`loader.S`](../threads/loader.S): 커널 로더, 시스템 부팅 처음에만 호출되고 512바이트짜리 바이오스 코드를 메모리에 올려놓은 뒤 [`start.S:bootstrap`](../threads/start.S) 코드로 점프한다. (`%rip`를 bootstrap 첫 줄로 옮긴다는 의미겠지?)
