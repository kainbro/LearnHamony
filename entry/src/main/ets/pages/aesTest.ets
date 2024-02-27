import router from '@ohos.router';
import PageTitle from '../view/PageTitle';
import { CipherModel } from '../utils/CipherModel';
import Logger from '../utils/Logger';

@Entry
@Component
struct aesTest {
  // 参考文献
  // https://blog.csdn.net/sumsear/article/details/135689973
  // https://www.cnblogs.com/testlearn/p/16547583.html
  // https://blog.csdn.net/m0_58411371/article/details/136166966
  // https://blog.csdn.net/qq_41437542/article/details/128468117

  // 加密实现
  // 加密（从前往后）：明文 -> 加密 -> base64处理 -> 密文
  // 解密实现
  // 解密（从后往前）：明文 <- 解密 <- base64处理 <- 密文

  TAG: string = '[aesTest]'

  @State title: string = router.getParams()?.['title'];
  @State originText: string = ""; // 明文
  @State cipherText: string = ""; // 密文
  @State decodedText: string = ""; // 密文解密
  private cipherModel: CipherModel = new CipherModel();

  // key 这个是aes加密用的密码，大家根据自己的项目选择生成密码的方法
  AES_ENCRYPT_KEY: string = '37016B038DEEED9FA6F866==';
  // iv 这个是aes加密用的偏移量，根据自己项目情况写
  AES_IV_STRING: string = 'ilovelearnhamony';

  build() {
    Column() {
      PageTitle({ titleName: this.title })

      Divider()
        .strokeWidth('1px')
        .color($r('sys.color.ohos_id_color_list_separator'))

      // 明文
      Column() {
        TextInput({ placeholder: "请输入原文" })
          .fontSize(18)
          .width('96%')
          .height(100)
          .padding(12)
        .onChange((value: string) => {
            this.originText = value;
          })

        // 加密按钮
        Row() {
          Button('aes加密').align(Alignment.Start)
        }.width('100%').margin({ left: 12, top: 12 })
        .onClick( () => {
          this.cipherModel.aesEncrypt(
            this.originText,
            this.AES_ENCRYPT_KEY,
            this.AES_IV_STRING,
            (result: string) => {
              Logger.info(this.TAG, `this result = ${JSON.stringify(result)}`);
              this.cipherText = result;
            })
        }
        )

        // 密文
        Text('加密后:')
          .fontSize(18)
          .fontColor('#1a1c1f')
          .padding(12)
          .width('100%')
          .align(Alignment.Start)

        Text(this.cipherText).width('96%').height(100).margin({top: 12}).backgroundColor(Color.Gray)

        // 解密后的密闻
        Row() {
          Button('aes解密').align(Alignment.Start)
        }.width('100%').margin({ left: 12, top: 12 })
        .onClick(() => {
          if(this.cipherText.toString().length === 0) {
            return;
          }
          this.cipherModel.aesDecrypt(this.cipherText,
            this.AES_ENCRYPT_KEY,
            this.AES_IV_STRING,
            (result: string) => {
            Logger.info(this.TAG, `this result = ${JSON.stringify(result)}`);
            this.decodedText = result;
          })
        })

        // 显示解密后的内容
        Text(this.decodedText).width('96%').height(100).margin({top: 12}).backgroundColor(Color.Gray)
      }
    }
  }
}

