#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <SDL2/SDL.h>

#define WIDTH  800
#define HEIGHT 600

#define SIZE 20 

#define ROWS (HEIGHT/SIZE) 
#define COLS (WIDTH/SIZE) 
#define MAX_LEN 1000

int running = 1;
int x=0,y=0;
SDL_Window* window = NULL;
SDL_Renderer* renderer= NULL;

void drawRect(int x,int y,Uint8 r, Uint8 g, Uint8 b)
{
	SDL_Rect rect = 
	{
		x,	
		y,	
		SIZE -1,
		SIZE -1
	};


	SDL_SetRenderDrawColor(renderer,r,g,b,255);
	SDL_RenderFillRect(renderer,&rect);
}


void renderGame()
{
	SDL_SetRenderDrawColor(renderer,0,0,0,255);
	SDL_RenderClear(renderer);

	drawRect(x++,y,0,255,0);

	if(x> 300)
	{
		running = 0;	
	}

	//drawRect(50,50,255,255,0);

	SDL_RenderPresent(renderer);
}



int main(int argc,char* argv[]) 
{
	srand(time(0));

	if(SDL_Init(SDL_INIT_VIDEO) != 0) 
	{
		printf("SDL_Init Error: %s\n", SDL_GetError());
		return 1;
	}

	SDL_Window* window = SDL_CreateWindow("SDL-Snake",
			                       SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 
					       WIDTH, HEIGHT, 
					       SDL_WINDOW_SHOWN);
	if(window == NULL) 
	{
		printf("SDL_CreateWindow Error: %s\n", SDL_GetError());
		return 1;
	}

	//renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
	renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED|SDL_RENDERER_PRESENTVSYNC);
	if(renderer == NULL) 
	{
		printf("SDL_CreateRenderer Error: %s\n", SDL_GetError());
		return 1;
	}

	SDL_Event e;

	while(running)
	{

		while(SDL_PollEvent(&e))
		{

			if(e.type == SDL_QUIT)
				running =0;

			if(e.type == SDL_KEYDOWN)
			{

				switch(e.key.keysym.sym)	
				{
					case SDLK_UP:
						break;


					case SDLK_DOWN:
						break;

					case SDLK_LEFT:
						break;



					case SDLK_RIGHT:
						break;


					default:
						break;


				}
			}


		}

		SDL_Log("heart beating\n");
		renderGame();
		SDL_Delay(1000);

	}


	SDL_DestroyRenderer(renderer);
	SDL_DestroyWindow(window);
	SDL_Quit();

	SDL_Log("Exit\n");
	return 0;








}

