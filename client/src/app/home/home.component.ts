import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})
export class HomeComponent implements OnInit{
  registermode = false;
  users : any;

  constructor() {}

  ngOnInit(): void {

  }

  registerToggle(){
    this.registermode = !this.registermode;
  }

  cancelRegisterMode(event: boolean) {
    this.registermode = event;
  }

}
