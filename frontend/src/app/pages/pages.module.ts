import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HomeComponent } from './home/home.component';
import { AuthModule } from '../auth/auth.module';

@NgModule({
  declarations: [HomeComponent],
  imports: [CommonModule, AuthModule],
})
export class PagesModule {}
