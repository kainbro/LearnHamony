import router from '@ohos.router';
import Constants from '../common/Constants';

@Component
export default struct PageTitle {
  @State titleName: string = "标题文字";

  build() {
    Row() {
      Image($r('app.media.back'))
        .width(20)
        .height(20)
        .onClick(() => {
          router.back()
        })
      Text(this.titleName)
        .fontSize(Constants.PAGE_TITLE_TEXT_SIZE)
        .width(Constants.PAGE_TITLE_TEXT_WIDTH)
        .maxLines(Constants.PAGE_TITLE_TEXT_MAX_LINES)
        .textOverflow({overflow: TextOverflow.Ellipsis})
        .margin({ left: 20 })
    }
    .padding(12)
    .width('100%')
  }
}