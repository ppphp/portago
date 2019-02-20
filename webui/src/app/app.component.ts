import { Component } from '@angular/core';
import { HttpClient} from "@angular/common/http";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  title = 'portago';
  constructor(private httpClient:HttpClient) {  };
  sync(){
    console.log("sync");
    this.httpClient.get("http://0.0.0.0:3000/sync?method=rsync").subscribe((data:any[]) => {console.log(data)})
  }
  cats(){
    console.log("cat");
    this.httpClient.get("http://0.0.0.0:3000/category").subscribe((data:any[]) => {console.log(data)})
  }
  build(){
    console.log("build");
    this.httpClient.get("http://0.0.0.0:3000/build").subscribe((data:any[]) => {console.log(data)})
  }
}
