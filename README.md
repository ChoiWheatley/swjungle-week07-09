Brand new pintos for Operating Systems and Lab (CS330), KAIST, by Youngjin Kwon.

The manual is available at <https://casys-kaist.github.io/pintos-kaist/>.

---

## README for README

본 문서는 필요한 정보를 한 곳에서 관리하기 위해 만들어졌습니다. 공지사항, URL 인덱싱, 브리핑 내용 정리로 사용할 예정입니다. 깃허브 이슈를 통해서 할 일 목록과 수정제안등을 할 수 있고, Pull Request를 통해서 본 리포지토리에 기여할 수 있습니다.

Project 3에서 팀이 섞이고 코드가 섞이기 때문에 혼란을 최소화 하기 위해 구현물에 대한 문서화를 확실히 해야할 것으로 보입니다. 따라서 [Coding Convention](#coding-convention) 쪽으로 가셔서 어떤 docstring 규격을 사용할건지, 어떤 포매터를 사용할건지 등에 대한 정보를 확인하시기 바랍니다.

- [\[WEEK07-11\] 정글 끝까지 (private)](https://jungle7-7610626261f4.herokuapp.com/pages/W07-os.html) | 학습범위, 일정, 팀 프로젝트등 여기에 없는 웬만한 건 저기에 다 있습니다.
- 권영진 교수님 강의 전 읽고 갈 것들
  - [Pintos_1.pdf](https://drive.google.com/file/d/1rr1VobnaR8QiWq3TVImvzzHWWdB5d4B5/view)
  - [01_os_review.pdf](https://drive.google.com/file/d/1v7ZT0uCqnSFQQY3jQsnXnCh9WHPpgQxZ/view?usp=sharing)
  - [CS 6200: Introduction to Operating Systems Course Videos (Georgia Tech College of Computing)](https://omscs.gatech.edu/cs-6200-introduction-operating-systems-course-videos)
- [진행상황 구글 스프레드시트 (private)](https://docs.google.com/spreadsheets/d/1SjVvI3bUMruBB_XWPMXSnzziP343g9UCFIphWU4D2iE/edit#gid=0)
- 공부자료
  - [Project 1: Thread 과제설명 {YT}](https://youtu.be/myO2bs5LMak?si=8SmqdzUOKnTZO2dc) | impl of alarm clock, priority scheduling, advanced scheduler
  - [PintOS 검색어(키워드) 목록 (private)](https://jungle7-7610626261f4.herokuapp.com/pages/pintos-keywords.html)
  - [OSTEP](https://pages.cs.wisc.edu/~remzi/OSTEP/)
- Q&As
  - [Project 1 Q&A (private)](https://jungle7-7610626261f4.herokuapp.com/pages/pintos-questions1.html)

## swjungle 공지사항

### 브리핑

- **10:00** 모닝 화이팅 및 오늘의 다짐 공유하는 시간
- **저녁(시간미정)** 학습기간 동안에는 공부한 것들에 대한 내용을 다루고 구현기간 동안에는 다 함께 머리를 맞댄 결과물에 대해서 이야기 나눌듯?

### 추석기간에 빠지는 날들

- @smi-23 2023-09-30 ~ 2023-10-01
- @coding-jjun 2023-09-27(저녁) ~ 2023-09-30
- @ChoiWheatley None

### 권영진 교수님의 OS 강의일정

- 2023-09-26T10:30:00 (7주차 화요일)
- 2023-10-10T10:30:00 (8주차 화요일)
- OS abstraction 개념에 초점을 맞추어 진행.
- 강의 슬라이드는 swjungle 페이지에서 확인바람.

## Weekly I learned

### Project1: Threads
  
[Project1 Threads](doc/Project1%20Threads.md)

### Project2: User Programs

[Project2 User Programs](doc/Project2%20User%20Program.md)

## Coding Convention

C 코드 포매팅 (`C_Cpp.clang_format_style`)은 LLVM을 사용합니다. 일단 자주 사용하는 파일만 전체 포매팅 돌렸습니다.

```json
{
  "C_Cpp.clang_format_style": "{ ColumnLimit: 80, IndentWidth: 4, TabWidth: 4 }",
  "C_Cpp.clang_format_fallbackStyle": "LLVM",
}
```

uninit.h 와 vm.h의 경우 각각 ifndef 구문으로 한번만 정의하도록 제한하고 있지만 내부적으로 include 헤더 위치에 따라서 순환문제가 발생합니다. 이 두 파일에 대해서는 전체 formatting을 수행하지 않아야 합니다.

formatting이 필요한 경우 일부 영역만 포매팅을 적용하는 "Format Selection"을 사용하도록 합니다.

[Doxygen Documentation Generator](https://marketplace.visualstudio.com/items?itemName=cschlosser.doxdocgen)를 사용하여 기존에 `///` 또는 `/***/`을 사용한 docstring 자동생성에 더 많은 기능과 자동완성을 제공해 줄 수 있습니다.

[Markdown Lint](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint)는 md파일을 작성할 때 파일 깨지는 현상을 사전에 방지해 줄 수 있습니다.

변수명, 전역변수, 정적변수 사용규칙까지 세세하게 강제하지는 않겠습니다. 하지만 팀원들의 코드가 일관적이 되도록 신경쓸 수 있다면 좋을 것 같습니다.

## Commit Convention

[git commit message 규칙](https://choiwheatley.github.io/git%20commit%20message%20%EA%B7%9C%EC%B9%99/) 참조

## Presentation

매 주차가 끝나는 날 오전에 발표를 진행한다고 합니다. 아직 정확히 어떤 발표를 진행한다는 건지 잘 모르겠어서 코치님한테 질문 남겼습니다.

> 맞습니다. 그래서 한 팀당 5분 이내로 공유를 끝내셔야 합니다.
특별히 팀 당 자료는 없지만 발표 전까지 개인별로 WIL (weekly I learned)을 작성하는 것을 확인하기는 합니다.

> 어떤 내용을 공유할 것인가는 팀에서 정하십시오. WIL 작성 내용도 마찬가지입니다.
사실 내용이 너무 많기 때문에 WIL을 적으라는 것입니다. 그렇지 않으면 잊어버릴 것이므로...
팀이 5분 내에 발표할 내용은 팀이 겪은 일, 학습한 내용 중에서 가장 인상적인 것을 발표하는 것이 자연스럽지 않을까 싶네요.

- [Project 1: 2023-10-03](#)
- [Project 2: 2023-10-10](#)

## File Structure

[//begin]: # "Autogenerated link references for markdown compatibility"
[synchronization]: doc/synchronization.md "Synchronization"
[Project1 Threads]: <doc/Project1 Threads.md> "Project1 Threads"
[//end]: # "Autogenerated link references"
