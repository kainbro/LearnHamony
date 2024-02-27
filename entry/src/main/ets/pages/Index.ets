import router from '@ohos.router';
import HomeListItem from '../view/HomeListItem';

@Entry
@Component
struct Index {
  @State message: string = 'Hello World';

  build() {
    Column() {

      HomeListItem({
        author: "paul",
        niceDate: "2024-02-27",
        title: "aes,des加解密",
        superChapterName: "基本功能",
        subChapterName: "加密"
      }).onClick(() => {
        router.pushUrl({
          url: 'pages/aesTest',
          params: {
            title: "aes,des加解密"
          }
        }, router.RouterMode.Single)
      })

      Divider();
    }
    .width('100%')
  }
}