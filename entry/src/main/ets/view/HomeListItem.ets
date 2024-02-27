import router from '@ohos.router';
import Constants from '../common/Constants';

@Component
export default struct HomeListItem {
  @State author: string = "";
  @State niceDate: string = "";
  @State title: string = "";
  @State superChapterName: string = "";
  @State subChapterName: string = "";

  build() {
    Column() {
      Row() {
        Text(this.author)
          .fontSize($r("app.float.list_item_font_size_2"))
          .fontColor($r('app.color.fontColor_text2'))
          .maxLines(Constants.LIST_ITEM_TEXT_MAX_LINES)
          .textOverflow({overflow: TextOverflow.None})

        Text(this.niceDate)
          .fontSize($r("app.float.list_item_font_size_2"))
          .fontColor($r('app.color.fontColor_text2'))
          .maxLines(Constants.LIST_ITEM_TEXT_MAX_LINES)
          .margin({right: Constants.LIST_ITEM_PADDING_RIGHT})
          .textOverflow({overflow: TextOverflow.None})
      }
      .width('96%')
      .margin({left: Constants.LIST_ITEM_PADDING_LEFT,
      right: Constants.LIST_ITEM_PADDING_RIGHT,
      top: Constants.LIST_ITEM_PADDING_TOP})
      .justifyContent(FlexAlign.SpaceBetween)

      Text(this.title)
        .fontSize($r("app.float.list_item_font_size_1"))
        .fontColor($r('app.color.fontColor_text1'))
        .maxLines(Constants.LIST_ITEM_TITLE_MAX_LINES)
        .margin({
          left: Constants.LIST_ITEM_PADDING_LEFT,
          right: Constants.LIST_ITEM_PADDING_RIGHT,
          top: Constants.LIST_ITEM_PADDING_TOP,
          bottom: Constants.LIST_ITEM_PADDING_TOP
        })
        .textOverflow({overflow: TextOverflow.Ellipsis})
        .fontWeight(Constants.LIST_ITEM_TITLE_FONT_WEIGHT)

      Row() {
        Text(this.superChapterName + '/')
          .fontSize($r('app.float.list_item_font_size_2'))
          .fontColor($r('app.color.fontColor_text2'))
          .maxLines(Constants.LIST_ITEM_TEXT_MAX_LINES)
          .textOverflow({overflow: TextOverflow.None})

        Text(this.subChapterName)
          .fontSize($r('app.float.list_item_font_size_2'))
          .fontColor($r('app.color.fontColor_text2'))
          .maxLines(Constants.LIST_ITEM_TEXT_MAX_LINES)
          .textOverflow({overflow: TextOverflow.None})
      }
      .margin({ left: Constants.LIST_ITEM_PADDING_LEFT,
      right: Constants.LIST_ITEM_PADDING_LEFT,
      bottom: Constants.LIST_ITEM_PADDING_TOP})
    }
    .backgroundColor($r('app.color.list_item_background'))
    .margin({top: Constants.LIST_ITEM_PADDING_TOP})
    .borderRadius(Constants.LIST_ITEM_BOARD_RADIUS)
    .alignItems(HorizontalAlign.Start)
  }
}